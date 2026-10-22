package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

// cmdSuperadmin implementa "envmem-server create-superadmin [--senha-stdin]
// EMAIL", que cria o primeiro superadmin. Roda direto no servidor, com o
// mesmo DATABASE_URL (envmem_app) do servidor; os superadmins seguintes são
// criados pela API.
func cmdSuperadmin(args []string) int {
	fs := flag.NewFlagSet("create-superadmin", flag.ContinueOnError)
	fromStdin := fs.Bool("senha-stdin", false, "lê a senha de uma linha do stdin, em vez de pedir no terminal")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Uso: envmem-server create-superadmin [--senha-stdin] EMAIL")
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

	password, err := readNewPassword(*fromStdin)
	// A senha só existe neste []byte: é zerada ao sair, depois do hash.
	defer clear(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server create-superadmin: %v\n", err)
		return 2
	}

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		fmt.Fprintln(os.Stderr, "envmem-server create-superadmin: DATABASE_URL não definida")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server create-superadmin: %v\n", err)
		return 1
	}
	defer st.Close()
	if err := st.CheckMigrated(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server create-superadmin: %v (rode envmem-server migrate)\n", err)
		return 1
	}

	email, err := createSuperadmin(ctx, st, fs.Arg(0), password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server create-superadmin: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "superadmin %s criado. Recomenda-se criar um segundo superadmin.\n", email)
	return 0
}

// superadminCreator é a parte do store que createSuperadmin usa (os testes
// usam uma versão em memória).
type superadminCreator interface {
	CreateFirstSuperadmin(ctx context.Context, email, passwordHash string) (store.User, error)
}

// createSuperadmin confere o e-mail e a senha, gera o hash e cria o
// usuário. Devolve o e-mail normalizado.
func createSuperadmin(ctx context.Context, st superadminCreator, rawEmail string, password []byte) (string, error) {
	email, err := auth.NormalizeEmail(rawEmail)
	if err != nil {
		return "", err
	}
	if err := auth.CheckPasswordPolicy(password); err != nil {
		return "", err
	}
	_, err = st.CreateFirstSuperadmin(ctx, email, auth.HashPassword(password))
	switch {
	case errors.Is(err, store.ErrSuperadminExists):
		return "", errors.New("já existe um superadmin; os seguintes são criados por ele, pela API")
	case errors.Is(err, store.ErrConflict):
		return "", fmt.Errorf("já existe um usuário com o e-mail %s", email)
	case err != nil:
		return "", err
	}
	return email, nil
}

// readNewPassword lê a senha nova. No terminal, pede duas vezes, sem eco
// (o que é digitado não aparece na tela nem fica no histórico do shell).
// Com --senha-stdin, lê uma linha do stdin, para uso em scripts; a senha
// nunca vem por argumento, porque argumentos aparecem no "ps".
func readNewPassword(fromStdin bool) ([]byte, error) {
	if fromStdin {
		return readLine(os.Stdin)
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("o stdin não é um terminal; use --senha-stdin para ler a senha de um pipe")
	}
	fmt.Fprintf(os.Stderr, "Senha (de %d a %d caracteres): ", auth.MinPasswordLen, auth.MaxPasswordLen)
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(os.Stderr, "Repita a senha: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	defer clear(second)
	if err != nil {
		clear(first)
		return nil, err
	}
	if !bytes.Equal(first, second) {
		clear(first)
		return nil, errors.New("as senhas não conferem")
	}
	return first, nil
}

// readLine lê uma linha de r, sem o "\n" (nem o "\r" do Windows).
func readLine(r io.Reader) ([]byte, error) {
	line, err := bufio.NewReader(r).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}
