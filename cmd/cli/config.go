package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/heschaefer/envmem/internal/client"
)

// defaultServer é o endereço usado enquanto não existe o arquivo de
// configuração gravado pelo "envmem login" (Fatia 5).
const defaultServer = "https://localhost:8080"

// connFlags são as flags de conexão com o servidor, comuns a todos os
// subcomandos. Na Fatia 5, os valores padrão passam a vir do config.json, e
// as flags ficam como sobrescrita.
type connFlags struct {
	servidor string
	ca       string
}

func addConnFlags(fs *flag.FlagSet) *connFlags {
	f := &connFlags{}
	fs.StringVar(&f.servidor, "servidor", defaultServer, "endereço do envmem-server")
	fs.StringVar(&f.ca, "ca", "", "certificado da CA do envmem (ca.crt); vazio usa as CAs do sistema")
	return f
}

// authedClient cria o cliente da API já com o token da sessão gravada por
// "envmem login".
func (f *connFlags) authedClient() (*client.Client, error) {
	token, err := loadToken()
	if err != nil {
		return nil, err
	}
	c, err := f.client()
	if err != nil {
		return nil, err
	}
	c.SetToken(token)
	return c, nil
}

// printError mostra um erro do CLI e, para os erros de sessão, diz o que
// fazer.
func printError(err error) {
	fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		return
	}
	switch {
	case apiErr.Code == "unauthorized":
		fmt.Fprintln(os.Stderr, "envmem: rode envmem login")
	case apiErr.Code == "password_change_required":
		fmt.Fprintln(os.Stderr, "envmem: rode envmem login num terminal para trocar a senha temporária")
	}
}

// client cria o cliente da API com os valores das flags.
func (f *connFlags) client() (*client.Client, error) {
	var roots *x509.CertPool
	if f.ca != "" {
		var err error
		if roots, err = client.LoadCA(f.ca); err != nil {
			return nil, err
		}
	}
	return client.New(f.servidor, roots)
}
