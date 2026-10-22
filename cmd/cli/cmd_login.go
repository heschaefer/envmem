package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"
)

// cmdLogin implementa "envmem login [opções] EMAIL": pede a senha, abre uma
// sessão no servidor e grava o token em ~/.config/envmem/token (600).
func cmdLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	conn := addConnFlags(fs)
	fromStdin := fs.Bool("senha-stdin", false, "lê a senha de uma linha do stdin, em vez de pedir no terminal")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Uso: envmem login [--servidor URL] [--ca ARQUIVO] [--senha-stdin] EMAIL")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	email := fs.Arg(0)

	c, err := conn.client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 2
	}
	password, err := readPassword("Senha: ", *fromStdin)
	defer clear(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.Login(ctx, email, string(password))
	if err != nil {
		printError(err)
		return 1
	}
	c.SetToken(res.Token)

	// Senha temporária (decisão 43): a sessão só serve para trocá-la, então
	// a troca acontece aqui mesmo, antes de gravar o token.
	if res.MustChangePassword {
		if err := changeTempPassword(ctx, c, password); err != nil {
			// Sem a troca, a sessão não serve para nada: é revogada.
			c.Logout(ctx)
			fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
			return 1
		}
	}

	if err := saveToken(res.Token); err != nil {
		c.Logout(ctx)
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "sessão iniciada; válida até %s\n", res.ExpiresAt.Local().Format("02/01 15:04"))
	return 0
}

// passwordChanger é a parte do cliente que changeTempPassword usa.
type passwordChanger interface {
	ChangePassword(ctx context.Context, current, next string) error
}

// changeTempPassword pede a senha nova e troca a temporária. Exige
// terminal: a senha nova é digitada duas vezes, sem eco.
func changeTempPassword(ctx context.Context, c passwordChanger, current []byte) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("a senha é temporária e precisa ser trocada; rode envmem login num terminal")
	}
	fmt.Fprintln(os.Stderr, "Sua senha é temporária. Escolha uma senha nova.")
	next, err := readNewPassword()
	defer clear(next)
	if err != nil {
		return err
	}
	if err := c.ChangePassword(ctx, string(current), string(next)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "senha trocada.")
	return nil
}
