package main

import (
	"errors"
	"fmt"
	"os"

	"charm.land/huh/v2"

	"github.com/heschaefer/envmem/internal/client"
)

// Ações de variáveis do modo interativo (gestor, admin e superadmin). Cada
// uma chama as mesmas funções e rotas do subcomando "envmem secrets"; o
// servidor confere a permissão de novo em todas.

// newKeyChoice é a opção "Nova variável" na lista de variáveis. Não pode
// ser confundida com um nome de verdade: o byte nulo nunca passa pelo
// envname.
const newKeyChoice = "\x00nova"

// canManageSecrets diz se o menu mostra ver valor, gravar e lixeira: gestor
// nos projetos dele, admin e superadmin em todos.
func canManageSecrets(role string) bool {
	return role == "gestor" || role == "admin" || role == "superadmin"
}

// canPurge diz se o menu mostra a exclusão definitiva: só admin e
// superadmin (decisão 11).
func canPurge(role string) bool {
	return role == "admin" || role == "superadmin"
}

// pickSecret mostra as variáveis do projeto e devolve o nome escolhido, ou
// "" para voltar. Com withNew, oferece também "Nova variável".
func pickSecret(c *client.Client, project, title string, withNew bool) (string, error) {
	ctx, cancel := apiContext()
	metas, err := c.SecretsMeta(ctx, project)
	cancel()
	if err != nil {
		return "", err
	}
	if len(metas) == 0 && !withNew {
		fmt.Fprintf(os.Stderr, "o projeto %s não tem variáveis\n", project)
		return "", nil
	}

	options := make([]huh.Option[string], 0, len(metas)+2)
	for _, m := range metas {
		options = append(options, huh.NewOption(fmt.Sprintf("%s (v%d)", m.Key, m.Version), m.Key))
	}
	if withNew {
		options = append(options, huh.NewOption("Nova variável", newKeyChoice))
	}
	options = append(options, huh.NewOption("Voltar", ""))

	choice := options[0].Value // cursor na primeira opção, não no Voltar
	err = huh.NewSelect[string]().Title(title).Options(options...).Value(&choice).Run()
	return choice, err
}

// showValue mostra o valor atual de uma variável. A leitura fica na
// auditoria (secret.read), como no "envmem secrets get".
func showValue(c *client.Client, project string) error {
	key, err := pickSecret(c, project, "Ver o valor de qual variável?", false)
	if err != nil || key == "" {
		return err
	}
	ctx, cancel := apiContext()
	defer cancel()
	s, err := c.Secret(ctx, project, key, 0)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s (versão %d):\n", s.Key, s.Version)
	fmt.Println(s.Value)
	return nil
}

// setSecret grava uma versão nova de uma variável existente ou cria uma
// nova, com o mesmo fluxo do "envmem secrets set": confere o nome e o
// estado antes de pedir o valor, confirma se a variável é nova ou está na
// lixeira, e pede o valor duas vezes, mascarado.
func setSecret(c *client.Client, project string) error {
	key, err := pickSecret(c, project, "Gravar qual variável?", true)
	if err != nil || key == "" {
		return err
	}
	if key == newKeyChoice {
		key = ""
		err := huh.NewInput().
			Title("Nome da variável").
			Description("Letras maiúsculas, dígitos e _, como DB_PASSWORD").
			Value(&key).
			Validate(checkKeyName).
			Run()
		if err != nil {
			return err
		}
	}

	ctx, cancel := apiContext()
	state, err := secretState(ctx, c, project, key)
	cancel()
	if err != nil {
		return err
	}
	if question := state.question(project, key); question != "" {
		ok := false
		err := huh.NewConfirm().Title(question).Affirmative("Sim").Negative("Não").Value(&ok).Run()
		if err != nil {
			return err
		}
		if !ok {
			return errCanceled
		}
	}

	value, err := readValueForm()
	if err != nil {
		return err
	}
	ctx, cancel = apiContext()
	defer cancel()
	return putSecret(ctx, c, project, key, value)
}

// readValueForm pede o valor duas vezes, com os caracteres mascarados. O
// huh devolve o valor como string, que o Go não deixa zerar; no subcomando,
// o valor fica num []byte zerado depois do uso, mas a cópia em string para
// o JSON também existe lá (decisão 48).
func readValueForm() (string, error) {
	var first, second string
	err := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Valor").
			Description("Não aparece na tela. Para valores com várias linhas, use envmem secrets set --valor-stdin.").
			EchoMode(huh.EchoModePassword).
			Value(&first).
			Validate(func(s string) error {
				if s == "" {
					return errors.New("o valor está vazio")
				}
				return nil
			}),
		huh.NewInput().
			Title("Repita o valor").
			EchoMode(huh.EchoModePassword).
			Value(&second).
			Validate(func(s string) error {
				if s != first {
					return errors.New("os valores não conferem")
				}
				return nil
			}),
	)).Run()
	return first, err
}

// trashSecret manda uma variável para a lixeira. Não pede confirmação:
// a lixeira é justamente o que permite desfazer.
func trashSecret(c *client.Client, project string) error {
	key, err := pickSecret(c, project, "Mandar qual variável para a lixeira?", false)
	if err != nil || key == "" {
		return err
	}
	ctx, cancel := apiContext()
	defer cancel()
	if err := c.TrashSecret(ctx, project, key); err != nil {
		return err
	}
	fmt.Printf("%s foi para a lixeira do projeto %s\n", key, project)
	return nil
}

// trashMenu lista a lixeira e, para a variável escolhida, oferece
// restaurar e, para admin e superadmin, excluir definitivamente.
func trashMenu(c *client.Client, project, role string) error {
	ctx, cancel := apiContext()
	trashed, err := c.Trash(ctx, project)
	cancel()
	if err != nil {
		return err
	}
	if len(trashed) == 0 {
		fmt.Fprintln(os.Stderr, "a lixeira está vazia")
		return nil
	}

	options := make([]huh.Option[string], 0, len(trashed)+1)
	for _, t := range trashed {
		label := fmt.Sprintf("%s (v%d, removida em %s)", t.Key, t.Version, t.DeletedAt.Local().Format("02/01/2006 15:04"))
		options = append(options, huh.NewOption(label, t.Key))
	}
	options = append(options, huh.NewOption("Voltar", ""))
	key := options[0].Value
	if err := huh.NewSelect[string]().Title("Lixeira de " + project).Options(options...).Value(&key).Run(); err != nil || key == "" {
		return err
	}

	const restore, purge, back = "restaurar", "excluir", ""
	actions := []huh.Option[string]{huh.NewOption("Restaurar", restore)}
	if canPurge(role) {
		actions = append(actions, huh.NewOption("Excluir definitivamente", purge))
	}
	actions = append(actions, huh.NewOption("Voltar", back))
	action := restore
	if err := huh.NewSelect[string]().Title(key).Options(actions...).Value(&action).Run(); err != nil {
		return err
	}

	switch action {
	case restore:
		ctx, cancel := apiContext()
		defer cancel()
		if err := c.RestoreSecret(ctx, project, key); err != nil {
			return err
		}
		fmt.Printf("%s restaurada no projeto %s\n", key, project)
	case purge:
		// No menu, a confirmação custa só uma tecla; no subcomando purge,
		// ela fica para quando o MFA existir (decisão 48).
		ok := false
		err := huh.NewConfirm().
			Title(fmt.Sprintf("Excluir %s definitivamente?", key)).
			Description("Todas as versões guardadas são apagadas, sem como desfazer.").
			Affirmative("Excluir").Negative("Cancelar").
			Value(&ok).Run()
		if err != nil {
			return err
		}
		if !ok {
			return errCanceled
		}
		ctx, cancel := apiContext()
		defer cancel()
		if err := c.PurgeSecret(ctx, project, key); err != nil {
			return err
		}
		fmt.Printf("%s excluída definitivamente do projeto %s\n", key, project)
	}
	return nil
}
