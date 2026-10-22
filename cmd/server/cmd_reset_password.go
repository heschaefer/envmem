package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

// cmdResetPassword implementa "envmem-server reset-password [--senha-stdin]
// EMAIL" (decisão 46): define uma senha temporária para o único
// superadmin, quando ele esqueceu a dele e não há outro superadmin para
// fazer o reset pela API. Roda direto no servidor.
//
// Não dá poder novo a ninguém: quem tem acesso ao servidor e ao
// DATABASE_URL já consegue alterar a tabela de usuários pelo psql. O
// comando troca esse caminho por um com regras (só superadmin, só sem
// outro superadmin, senha temporária, sessões revogadas).
func cmdResetPassword(args []string) int {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	fromStdin := fs.Bool("senha-stdin", false, "lê a senha temporária de uma linha do stdin, em vez de pedir no terminal")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Uso: envmem-server reset-password [--senha-stdin] EMAIL")
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
	defer clear(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server reset-password: %v\n", err)
		return 2
	}

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		fmt.Fprintln(os.Stderr, "envmem-server reset-password: DATABASE_URL não definida")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server reset-password: %v\n", err)
		return 1
	}
	defer st.Close()

	email, err := resetLoneSuperadmin(ctx, st, fs.Arg(0), password, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server reset-password: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "senha temporária definida para %s: troca obrigatória no próximo login, válida por 72 horas. Sessões abertas foram revogadas.\n", email)
	return 0
}

type loneSuperadminResetter interface {
	ResetLoneSuperadminPassword(ctx context.Context, email, passwordHash string, tempExpiresAt time.Time) (store.User, error)
}

// resetLoneSuperadmin confere o e-mail e a senha e faz o reset. Devolve o
// e-mail normalizado.
func resetLoneSuperadmin(ctx context.Context, st loneSuperadminResetter, rawEmail string, password []byte, now time.Time) (string, error) {
	email, err := auth.NormalizeEmail(rawEmail)
	if err != nil {
		return "", err
	}
	if err := auth.CheckPasswordPolicy(password); err != nil {
		return "", err
	}
	_, err = st.ResetLoneSuperadminPassword(ctx, email, auth.HashPassword(password), now.Add(auth.TempPasswordTTL))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", fmt.Errorf("não existe usuário %s", email)
	case errors.Is(err, store.ErrNotSuperadmin):
		return "", errors.New("este comando só redefine a senha de superadmin; os demais usuários são resetados por um superadmin, pela API")
	case errors.Is(err, store.ErrSuperadminExists):
		return "", errors.New("há outro superadmin: peça a ele o reset, pela API")
	case err != nil:
		return "", err
	}
	return email, nil
}
