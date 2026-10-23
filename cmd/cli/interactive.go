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
		{"Ver variáveis disponíveis (só nomes)", actListNames},
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

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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

		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		switch action {
		case actBack:
			cancel()
			return nil
		case actListNames:
			err = listNames(ctx, c, p.Name)
		}
		cancel()
		if err != nil {
			printError(err)
		}
	}
}

// listNames mostra os nomes das variáveis do projeto, sem os valores.
func listNames(ctx context.Context, c *client.Client, project string) error {
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
