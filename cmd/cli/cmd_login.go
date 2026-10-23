package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"github.com/heschaefer/envmem/internal/client"
)

// cmdLogin implementa "envmem login [opções] EMAIL": pede a senha, abre uma
// sessão no servidor e grava o token em ~/.config/envmem/token (600) e o
// endereço do servidor e a CA em ~/.config/envmem/config.json (decisão 38),
// que os próximos comandos usam sem precisar de --servidor e --ca.
func cmdLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	conn := addConnFlags(fs)
	fromStdin := fs.Bool("senha-stdin", false, "lê a senha (e, com MFA, o código) do stdin, uma linha cada, em vez de pedir no terminal")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Uso: envmem login [--servidor URL] [--ca ARQUIVO] [--senha-stdin] EMAIL")
		fmt.Fprintln(fs.Output(), "Com MFA e --senha-stdin, o código do app vai na linha seguinte à da senha.")
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

	cfg, err := conn.resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 2
	}
	// O config.json é lido de qualquer pasta, então o caminho relativo
	// passado em --ca (por exemplo, certs/ca.crt) vira absoluto.
	if cfg.CA != "" {
		if cfg.CA, err = filepath.Abs(cfg.CA); err != nil {
			fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
			return 2
		}
	}
	c, err := newClient(cfg)
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

	ctx, cancel := apiContext()
	res, err := c.Login(ctx, email, string(password))
	cancel()
	if err == nil {
		res, err = completeMFA(c, res, terminalMFA{fromStdin: *fromStdin})
	}
	if err != nil {
		printError(err)
		return 1
	}
	if err := openSession(c, cfg, res, string(password), terminalNewPassword); err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 1
	}
	return 0
}

// openSession completa um login aceito, no subcomando e no modo
// interativo: troca a senha temporária, se for o caso, e grava o
// config.json e o token. newPassword pede a senha nova (no terminal ou no
// formulário do huh).
//
// Se algo falhar depois do login, a sessão é revogada: sem a troca da
// senha temporária, ela não serve para nada (decisão 43), e uma sessão que
// não ficou gravada não teria como ser encerrada pelo logout.
func openSession(c *client.Client, cfg cliConfig, res client.LoginResult, current string, newPassword func() (string, error)) error {
	c.SetToken(res.Token)
	revoke := func() {
		ctx, cancel := apiContext()
		c.Logout(ctx)
		cancel()
	}

	// Senha temporária (decisão 43): a troca acontece aqui mesmo, antes de
	// gravar o token. O prazo da requisição começa depois da digitação.
	if res.MustChangePassword {
		next, err := newPassword()
		if err == nil {
			ctx, cancel := apiContext()
			err = c.ChangePassword(ctx, current, next)
			cancel()
		}
		if err != nil {
			revoke()
			return err
		}
		fmt.Fprintln(os.Stderr, "senha trocada.")
	}

	// A configuração só é gravada depois do login aceito: um endereço
	// digitado errado não substitui um config.json que funcionava.
	if err := saveConfig(cfg); err != nil {
		revoke()
		return err
	}
	if err := saveToken(res.Token); err != nil {
		revoke()
		return err
	}
	fmt.Fprintf(os.Stderr, "sessão iniciada; válida até %s\n", res.ExpiresAt.Local().Format("02/01 15:04"))
	return nil
}

// terminalNewPassword pede, no terminal, a senha nova que substitui a
// temporária. Exige terminal: a senha nova é digitada duas vezes, sem eco.
func terminalNewPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("a senha é temporária e precisa ser trocada; rode envmem login num terminal")
	}
	fmt.Fprintln(os.Stderr, "Sua senha é temporária. Escolha uma senha nova.")
	next, err := readNewPassword()
	defer clear(next)
	if err != nil {
		return "", err
	}
	return string(next), nil
}
