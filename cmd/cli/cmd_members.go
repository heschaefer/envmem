package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/heschaefer/envmem/internal/client"
)

// cmdMembers implementa "envmem members list|add|rm". Quem pode o quê
// (o gestor só mexe com desenvolvedores; nomear gestores é de admin e
// superadmin) é conferido no servidor.
func cmdMembers(args []string) int {
	if len(args) == 0 {
		membersUsage(os.Stderr)
		return 2
	}
	action, args := args[0], args[1:]

	// list não tem argumento; add e rm recebem o e-mail.
	var wantEmail bool
	switch action {
	case "list":
	case "add", "rm":
		wantEmail = true
	case "help", "-h", "-help", "--help":
		membersUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "envmem members: ação desconhecida %q\n\n", action)
		membersUsage(os.Stderr)
		return 2
	}

	fs := flag.NewFlagSet("members "+action, flag.ContinueOnError)
	projeto := fs.String("projeto", "", "projeto (obrigatório)")
	conn := addConnFlags(fs)
	var papel string
	if action == "add" {
		fs.StringVar(&papel, "papel", "desenvolvedor", `papel no projeto: "desenvolvedor" ou "gestor"`)
	}
	fs.Usage = func() {
		if wantEmail {
			fmt.Fprintf(fs.Output(), "Uso: envmem members %s --projeto X [opções] EMAIL\n", action)
		} else {
			fmt.Fprintf(fs.Output(), "Uso: envmem members %s --projeto X [opções]\n", action)
		}
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if (wantEmail && fs.NArg() != 1) || (!wantEmail && fs.NArg() != 0) || *projeto == "" {
		fs.Usage()
		return 2
	}

	c, err := conn.authedClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	switch action {
	case "list":
		err = membersList(ctx, c, *projeto, os.Stdout)
	case "add":
		var m client.Member
		if m, err = c.SetMember(ctx, *projeto, fs.Arg(0), papel); err == nil {
			fmt.Printf("%s é %s no projeto %s\n", m.Email, m.Role, *projeto)
		}
	case "rm":
		err = membersRemove(ctx, c, *projeto, fs.Arg(0))
		if err == nil {
			fmt.Printf("%s não é mais membro do projeto %s\n", fs.Arg(0), *projeto)
		}
	}
	if err != nil {
		printError(err)
		return 1
	}
	return 0
}

// membersList imprime um membro por linha: e-mail e papel.
func membersList(ctx context.Context, c *client.Client, project string, w io.Writer) error {
	members, err := c.Members(ctx, project)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		fmt.Fprintln(os.Stderr, "o projeto não tem membros")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, m := range members {
		fmt.Fprintf(tw, "%s\t%s\n", m.Email, m.Role)
	}
	return tw.Flush()
}

// membersRemove tira um membro pelo e-mail. A rota do servidor recebe o
// id (o caminho vai para o log, o e-mail não deve), então o id é buscado
// na lista de membros do projeto, que o gestor pode ver; a lista de
// usuários é só do superadmin.
func membersRemove(ctx context.Context, c *client.Client, project, email string) error {
	members, err := c.Members(ctx, project)
	if err != nil {
		return err
	}
	// O servidor guarda o e-mail em minúsculas.
	email = strings.ToLower(strings.TrimSpace(email))
	for _, m := range members {
		if m.Email == email {
			return c.RemoveMember(ctx, project, m.UserID)
		}
	}
	return fmt.Errorf("%s não é membro do projeto %s", email, project)
}

func membersUsage(w io.Writer) {
	fmt.Fprint(w, `Uso: envmem members <ação> --projeto X [opções] [EMAIL]

Ações:
  list         lista os membros do projeto e o papel de cada um
  add EMAIL    adiciona o usuário ao projeto, ou troca o papel dele
               (--papel desenvolvedor, o padrão, ou --papel gestor)
  rm EMAIL     tira o usuário do projeto

O gestor adiciona e remove desenvolvedores nos projetos dele. Nomear,
rebaixar ou remover gestores é de admin e superadmin. O usuário precisa
existir (envmem users create, feito por um superadmin).
`)
}
