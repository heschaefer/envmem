package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"charm.land/huh/v2"

	"github.com/heschaefer/envmem/internal/client"
)

// O modo interativo (Fatia 5b, decisão 37) é o "envmem" sem argumentos:
// menus navegáveis pelas setas, com o huh. É só uma camada: cada ação chama
// as mesmas funções dos subcomandos, que chamam as mesmas rotas da API.
//
// O menu esconde o que o papel não permite, mas isso é conforto, não
// controle de acesso: quem decide é o servidor, que confere cada rota no
// RBAC. Um menu adulterado só levaria a um 403.
//
// O huh desenha os menus no stderr; o stdout fica para a saída das ações
// (como a lista de variáveis), do mesmo jeito que nos subcomandos.

// requestTimeout é o prazo de cada chamada à API feita pelo menu. Não vale
// enquanto o usuário está num formulário: o prazo é por requisição.
const requestTimeout = 15 * time.Second

// menuAction é uma ação do menu de um projeto.
type menuAction int

const (
	actBack menuAction = iota
	actListNames
	actRun
	actShowValue
	actSetSecret
	actTrashSecret
	actTrash
)

// actionItem é uma opção do menu: o texto mostrado e a ação.
type actionItem struct {
	label  string
	action menuAction
}

// projectActions devolve as opções do menu de um projeto para o papel de
// quem está logado nele (desenvolvedor, gestor, admin ou superadmin).
// Esconder uma opção não impede a ação: o servidor confere de novo.
func projectActions(role string) []actionItem {
	items := []actionItem{
		{"Rodar um comando", actRun},
		{"Ver variáveis disponíveis (só nomes)", actListNames},
	}
	if canManageSecrets(role) {
		trash := "Ver a lixeira (restaurar)"
		if canPurge(role) {
			trash = "Ver a lixeira (restaurar ou excluir de vez)"
		}
		items = append(items,
			actionItem{"Ver o valor de uma variável", actShowValue},
			actionItem{"Gravar uma variável", actSetSecret},
			actionItem{"Mandar uma variável para a lixeira", actTrashSecret},
			actionItem{trash, actTrash},
		)
	}
	return append(items, actionItem{"Voltar", actBack})
}

// cmdInteractive abre o modo interativo. Só é chamado com terminal no
// stdin e no stdout (ver run).
func cmdInteractive() int {
	// Sem flags: servidor e CA vêm do config.json gravado pelo login.
	conn := addConnFlags(flag.NewFlagSet("envmem", flag.ContinueOnError))
	c, err := conn.authedClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 1
	}

	ctx, cancel := apiContext()
	me, err := c.Me(ctx)
	cancel()
	if err != nil {
		printError(err)
		return 1
	}

	for {
		project, ok, err := pickProject(c, me)
		if errors.Is(err, huh.ErrUserAborted) || (err == nil && !ok) {
			return 0
		}
		if err != nil {
			printError(err)
			return 1
		}
		if err := projectMenu(c, project); errors.Is(err, huh.ErrUserAborted) {
			return 0
		} else if err != nil {
			printError(err)
			return 1
		}
	}
}

// pickProject mostra os projetos de quem está logado, com o papel em cada
// um, e devolve o escolhido. ok é falso se a escolha foi sair.
func pickProject(c *client.Client, me client.Me) (client.Project, bool, error) {
	ctx, cancel := apiContext()
	projects, err := c.Projects(ctx)
	cancel()
	if err != nil {
		return client.Project{}, false, err
	}

	title := "envmem: " + me.Email
	if me.GlobalRole != "" {
		title += " (" + me.GlobalRole + ")"
	}
	description := "Escolha um projeto"
	if len(projects) == 0 {
		description = "Você não tem acesso a nenhum projeto; peça a um gestor ou admin"
	}

	// O índice -1 é "Sair"; os outros apontam para a lista de projetos.
	options := make([]huh.Option[int], 0, len(projects)+1)
	for i, p := range projects {
		options = append(options, huh.NewOption(fmt.Sprintf("%s (%s)", p.Name, p.Role), i))
	}
	options = append(options, huh.NewOption("Sair", -1))

	// O huh abre com o cursor na opção igual ao valor inicial: começa no
	// primeiro projeto, para que um Enter distraído não saia do programa.
	choice := -1
	if len(projects) > 0 {
		choice = 0
	}
	err = huh.NewSelect[int]().Title(title).Description(description).Options(options...).Value(&choice).Run()
	if err != nil || choice < 0 {
		return client.Project{}, false, err
	}
	return projects[choice], true, nil
}

// projectMenu mostra as ações do projeto até o usuário voltar. Um erro da
// API numa ação (como um 403) é mostrado e o menu continua; só sair do
// formulário (Ctrl+C) encerra.
func projectMenu(c *client.Client, p client.Project) error {
	items := projectActions(p.Role)
	options := make([]huh.Option[menuAction], 0, len(items))
	for _, it := range items {
		options = append(options, huh.NewOption(it.label, it.action))
	}

	for {
		// Cursor na primeira ação, não no "Voltar" (ver pickProject).
		action := items[0].action
		err := huh.NewSelect[menuAction]().
			Title(fmt.Sprintf("%s (%s)", p.Name, p.Role)).
			Options(options...).
			Value(&action).
			Run()
		if err != nil {
			return err
		}

		switch action {
		case actBack:
			return nil
		case actListNames:
			err = listNames(c, p.Name)
		case actRun:
			err = runCommand(c, p.Name)
		case actShowValue:
			err = showValue(c, p.Name)
		case actSetSecret:
			err = setSecret(c, p.Name)
		case actTrashSecret:
			err = trashSecret(c, p.Name)
		case actTrash:
			err = trashMenu(c, p.Name, p.Role)
		}
		if errors.Is(err, huh.ErrUserAborted) {
			return err
		}
		if errors.Is(err, errCanceled) {
			fmt.Fprintln(os.Stderr, "cancelado")
			continue
		}
		if err != nil {
			printError(err)
		}
	}
}

// apiContext é o prazo de uma chamada à API. Cada ação cria o seu só na
// hora de chamar, depois dos formulários: o tempo que o usuário leva
// digitando não conta.
func apiContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

// listNames mostra os nomes das variáveis do projeto, sem os valores.
func listNames(c *client.Client, project string) error {
	ctx, cancel := apiContext()
	defer cancel()
	metas, err := c.SecretsMeta(ctx, project)
	if err != nil {
		return err
	}
	if len(metas) == 0 {
		fmt.Fprintf(os.Stderr, "o projeto %s não tem variáveis\n", project)
		return nil
	}
	return writeMetas(os.Stdout, "", metas)
}

// runCommand pede um comando e o executa com os segredos do projeto, como
// "envmem run": busca os segredos e chama o syscall.Exec, e o processo do
// envmem (com o menu) vira a aplicação, no mesmo PID. Se der certo, não
// retorna; se o exec falhar (comando inexistente, por exemplo), o erro
// volta para o menu.
func runCommand(c *client.Client, project string) error {
	var line string
	err := huh.NewInput().
		Title("Comando").
		Description("Roda direto, sem shell: sem pipes, redirecionamentos nem $VARIÁVEIS. Aspas agrupam argumentos.").
		Placeholder("npm run dev").
		Value(&line).
		Validate(func(s string) error {
			_, err := splitCommand(s)
			return err
		}).
		Run()
	if err != nil {
		return err
	}
	command, err := splitCommand(line)
	if err != nil {
		return err
	}

	ctx, cancel := apiContext()
	secrets, err := c.Secrets(ctx, project)
	cancel()
	if err != nil {
		return err
	}
	// O mesmo caminho do subcomando run (inject.go), sem --verbose.
	return execWithSecrets(command, secrets, false)
}
