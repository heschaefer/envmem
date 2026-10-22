package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/heschaefer/envmem/internal/client"
)

// cmdLogout implementa "envmem logout": revoga a sessão no servidor e apaga
// o arquivo do token (decisão 4).
func cmdLogout(args []string) int {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	conn := addConnFlags(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	path, err := tokenPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 1
	}
	// Lê sem conferir a permissão: mesmo com o arquivo exposto, a sessão
	// precisa ser revogada.
	token, err := readToken(path)
	if errors.Is(err, errNoSession) {
		fmt.Fprintln(os.Stderr, "nenhuma sessão aberta")
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 1
	}

	revoked := true
	c, err := conn.client()
	if err == nil {
		c.SetToken(token)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = c.Logout(ctx)
		cancel()
	}
	var apiErr *client.APIError
	if err != nil && !(errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized) {
		// 401 quer dizer que a sessão já não valia (vencida ou revogada):
		// o resultado é o mesmo. Qualquer outro erro é avisado, porque aí
		// a sessão continua válida no servidor.
		revoked = false
		fmt.Fprintf(os.Stderr, "envmem: não foi possível revogar a sessão no servidor: %v\n", err)
	}

	if err := deleteToken(); err != nil {
		fmt.Fprintf(os.Stderr, "envmem: apagar o token: %v\n", err)
		return 1
	}
	if !revoked {
		fmt.Fprintln(os.Stderr, "envmem: o token foi apagado deste computador, mas a sessão continua válida no servidor até vencer (no máximo 8 horas)")
		return 1
	}
	fmt.Fprintln(os.Stderr, "sessão encerrada")
	return 0
}
