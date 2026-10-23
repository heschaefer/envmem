package main

import (
	"context"
	"errors"
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

// menuAction é uma ação do menu (de um projeto, de um membro ou global; as
// duas últimas ficam em interactive_admin.go).
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
	if isManager(role) {
		trash := "Ver a lixeira (restaurar)"
		if isAdmin(role) {
			trash = "Ver a lixeira (restaurar ou excluir de vez)"
		}
		items = append(items,
			actionItem{"Ver o valor de uma variável", actShowValue},
			actionItem{"Gravar uma variável", actSetSecret},
			actionItem{"Mandar uma variável para a lixeira", actTrashSecret},
			actionItem{trash, actTrash},
			actionItem{"Membros do projeto", actMembers},
		)
	}
	return append(items, actionItem{"Voltar", actBack})
}

// cmdInteractive abre o modo interativo. Só é chamado com terminal no
// stdin e no stdout (ver run).
func cmdInteractive() int {
	// Sessão válida, ou login pelo formulário (interactive_login.go).
	c, me, err := interactiveSession()
	if isAbort(err) {
		return 0
	}
	if err != nil {
		printError(err)
		return 1
	}

	// Um erro numa ação (como um 403 ou um 409) é mostrado e o menu
	// continua; só Ctrl+C ou "Sair" encerram.
	for {
		choice, projects, err := mainMenu(c, me)
		if err == nil {
			switch choice.action {
			case actQuit:
				return 0
			case actOpenProject:
				err = projectMenu(c, projects[choice.project])
			case actCreateProject:
				err = createProject(c)
			case actDeleteProject:
				err = deleteProject(c, projects)
			case actUsers:
				err = usersMenu(c)
			}
		}
		switch {
		case isAbort(err):
			return 0
		case isCanceled(err):
			fmt.Fprintln(os.Stderr, "cancelado")
		case err != nil:
			printError(err)
		}
	}
}

// mainChoice é uma opção do menu principal: um projeto (pelo índice na
// lista) ou uma ação global.
type mainChoice struct {
	project int
	action  menuAction
}

// mainMenu mostra os projetos de quem está logado, com o papel em cada um,
// e abaixo as ações globais do papel global. Devolve a escolha e a lista
// de projetos a que o índice se refere.
func mainMenu(c *client.Client, me client.Me) (mainChoice, []client.Project, error) {
	ctx, cancel := apiContext()
	projects, err := c.Projects(ctx)
	cancel()
	if err != nil {
		return mainChoice{}, nil, err
	}

	title := "envmem: " + me.Email
	if me.GlobalRole != "" {
		title += " (" + me.GlobalRole + ")"
	}
	description := "Escolha um projeto"
	if len(projects) == 0 {
		description = "Você não tem acesso a nenhum projeto; peça a um gestor ou admin"
	}

	options := make([]huh.Option[mainChoice], 0, len(projects)+4)
	for i, p := range projects {
		options = append(options, huh.NewOption(fmt.Sprintf("%s (%s)", p.Name, p.Role), mainChoice{i, actOpenProject}))
	}
	for _, it := range globalActions(me.GlobalRole) {
		options = append(options, huh.NewOption(it.label, mainChoice{-1, it.action}))
	}

	// O huh abre com o cursor na opção igual ao valor inicial: começa na
	// primeira, para que um Enter distraído não saia do programa.
	choice := options[0].Value
	err = huh.NewSelect[mainChoice]().Title(title).Description(description).Options(options...).Value(&choice).Run()
	return choice, projects, err
}

// isAbort diz se o usuário saiu de um formulário (Ctrl+C), o que encerra o
// modo interativo.
func isAbort(err error) bool {
	return errors.Is(err, huh.ErrUserAborted)
}

// isCanceled diz se o usuário respondeu não a uma confirmação.
func isCanceled(err error) bool {
	return errors.Is(err, errCanceled)
}

// projectMenu mostra as ações do projeto até o usuário voltar. Um erro da
// API numa ação (como um 403) é mostrado e o menu continua; só sair do
// formulário (Ctrl+C) encerra o modo interativo.
func projectMenu(c *client.Client, p client.Project) error {
	items := projectActions(p.Role)
	options := make([]huh.Option[menuAction], 0, len(items))
	for _, it := range items {
		options = append(options, huh.NewOption(it.label, it.action))
	}

	for {
		// Cursor na primeira ação, não no "Voltar" (ver mainMenu).
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
		case actMembers:
			err = membersMenu(c, p.Name, p.Role)
		}
		switch {
		case isAbort(err):
			return err
		case isCanceled(err):
			fmt.Fprintln(os.Stderr, "cancelado")
		case err != nil:
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
