package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/heschaefer/envmem/internal/client"
)

// cmdProjects implementa "envmem projects list|create|delete".
func cmdProjects(args []string) int {
	if len(args) == 0 {
		projectsUsage(os.Stderr)
		return 2
	}
	action, args := args[0], args[1:]

	// list não tem argumento; create e delete recebem o nome do projeto.
	var wantName bool
	switch action {
	case "list":
	case "create", "delete":
		wantName = true
	case "help", "-h", "-help", "--help":
		projectsUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "envmem projects: ação desconhecida %q\n\n", action)
		projectsUsage(os.Stderr)
		return 2
	}

	fs := flag.NewFlagSet("projects "+action, flag.ContinueOnError)
	conn := addConnFlags(fs)
	fs.Usage = func() {
		if wantName {
			fmt.Fprintf(fs.Output(), "Uso: envmem projects %s [opções] NOME\n", action)
		} else {
			fmt.Fprintf(fs.Output(), "Uso: envmem projects %s [opções]\n", action)
		}
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if (wantName && fs.NArg() != 1) || (!wantName && fs.NArg() != 0) {
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
		err = projectsList(ctx, c, os.Stdout)
	case "create":
		var p client.Project
		p, err = c.CreateProject(ctx, fs.Arg(0))
		if err == nil {
			fmt.Printf("projeto %s criado\n", p.Name)
		}
	case "delete":
		err = c.DeleteProject(ctx, fs.Arg(0))
		if err == nil {
			fmt.Printf("projeto %s removido\n", fs.Arg(0))
		}
	}
	if err != nil {
		printError(err)
		return 1
	}
	return 0
}

// projectsList imprime um projeto por linha, só o nome, para que a saída
// possa ser usada em scripts.
func projectsList(ctx context.Context, c *client.Client, w io.Writer) error {
	projects, err := c.Projects(ctx)
	if err != nil {
		return err
	}
	for _, p := range projects {
		fmt.Fprintln(w, p.Name)
	}
	return nil
}

func projectsUsage(w io.Writer) {
	fmt.Fprint(w, `Uso: envmem projects <ação> [opções] [NOME]

Ações:
  list           lista os projetos
  create NOME    cria um projeto (minúsculas, dígitos e hífen)
  delete NOME    remove um projeto sem segredos

As opções (como --servidor) vêm antes do nome:
  envmem projects create --servidor URL app-homo
`)
}
