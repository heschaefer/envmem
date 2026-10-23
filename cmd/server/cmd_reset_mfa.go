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

// cmdResetMFA implementa "envmem-server reset-mfa EMAIL" (decisão 36):
// apaga o MFA do único superadmin, quando ele perdeu o app autenticador
// (ou teve o MFA travado) e não há outro superadmin para fazer o reset
// pela API. Roda direto no servidor. No próximo login, ele cadastra o app
// de novo; as sessões abertas são revogadas.
//
// Como o reset-password, não dá poder novo: quem tem acesso ao servidor e
// ao DATABASE_URL já consegue apagar a linha pelo psql. O comando troca
// esse caminho por um com regras e auditoria.
func cmdResetMFA(args []string) int {
	fs := flag.NewFlagSet("reset-mfa", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Uso: envmem-server reset-mfa EMAIL")
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

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		fmt.Fprintln(os.Stderr, "envmem-server reset-mfa: DATABASE_URL não definida")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server reset-mfa: %v\n", err)
		return 1
	}
	defer st.Close()

	email, err := resetLoneSuperadminMFA(ctx, st, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server reset-mfa: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "MFA de %s apagado: o app é cadastrado de novo no próximo login. Sessões abertas foram revogadas.\n", email)
	return 0
}

type loneSuperadminMFAResetter interface {
	ResetLoneSuperadminMFA(ctx context.Context, email string) (store.User, error)
}

// resetLoneSuperadminMFA confere o e-mail e faz o reset. Devolve o e-mail
// normalizado.
func resetLoneSuperadminMFA(ctx context.Context, st loneSuperadminMFAResetter, rawEmail string) (string, error) {
	email, err := auth.NormalizeEmail(rawEmail)
	if err != nil {
		return "", err
	}
	_, err = st.ResetLoneSuperadminMFA(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", fmt.Errorf("não existe usuário %s, ou ele não tem MFA cadastrado", email)
	case errors.Is(err, store.ErrNotSuperadmin):
		return "", errors.New("este comando só reseta o MFA de superadmin; os demais são resetados por um superadmin, pela API")
	case errors.Is(err, store.ErrSuperadminExists):
		return "", errors.New("há outro superadmin: peça a ele o reset, pela API")
	case err != nil:
		return "", err
	}
	return email, nil
}
