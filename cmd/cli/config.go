package main

import (
	"flag"

	"github.com/heschaefer/envmem/internal/client"
)

// defaultServer é o endereço usado enquanto não existe o arquivo de
// configuração gravado pelo "envmem login" (Fatia 5).
const defaultServer = "http://localhost:8080"

// connFlags são as flags de conexão com o servidor, comuns a todos os
// subcomandos. Na Fatia 5, os valores padrão passam a vir do config.json, e
// as flags ficam como sobrescrita.
type connFlags struct {
	servidor string
}

func addConnFlags(fs *flag.FlagSet) *connFlags {
	f := &connFlags{}
	fs.StringVar(&f.servidor, "servidor", defaultServer, "endereço do envmem-server")
	return f
}

// client cria o cliente da API com os valores das flags.
func (f *connFlags) client() (*client.Client, error) {
	return client.New(f.servidor)
}
