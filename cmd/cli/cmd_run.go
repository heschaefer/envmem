package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// cmdRun implementa "envmem run --projeto X -- comando args".
// Se der certo, não retorna: o processo vira o comando (ver inject.go).
func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	projeto := fs.String("projeto", "", "projeto cujos segredos serão injetados (obrigatório)")
	conn := addConnFlags(fs)
	verbose := fs.Bool("verbose", false, "mostra o PID e o binário antes do exec")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Uso: envmem run --projeto X [--servidor URL] [--verbose] -- comando [args...]")
		fs.PrintDefaults()
	}
	// O flag para de ler opções no "--"; o que vem depois é o comando,
	// mesmo que tenha flags próprias (por exemplo, "-- ls -la").
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	command := fs.Args()
	if *projeto == "" || len(command) == 0 {
		fs.Usage()
		return 2
	}

	c, err := conn.client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	secrets, err := c.Secrets(ctx, *projeto)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 1
	}

	err = execWithSecrets(command, secrets, *verbose)

	// Só chega aqui se o exec não aconteceu.
	fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
	if errors.Is(err, exec.ErrNotFound) {
		return 127 // mesmo código que o shell usa para "comando não encontrado"
	}
	return 1
}
