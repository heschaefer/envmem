// Package config lê a configuração do envmem-server a partir de variáveis de
// ambiente, com flags de linha de comando que as sobrescrevem.
package config

import (
	"flag"
	"io"
	"os"
)

// Server é a configuração do envmem-server.
type Server struct {
	// ListenAddr é o endereço onde o servidor escuta, como ":8080".
	ListenAddr string
}

// LoadServer lê as variáveis de ambiente e aplica as flags de args por cima.
// Precedência: flag > variável de ambiente > valor padrão.
func LoadServer(args []string, stderr io.Writer) (Server, error) {
	cfg := Server{
		ListenAddr: envOr("ENVMEM_LISTEN_ADDR", ":8080"),
	}

	fs := flag.NewFlagSet("envmem-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "endereço de escuta (ou ENVMEM_LISTEN_ADDR)")
	if err := fs.Parse(args); err != nil {
		return Server{}, err
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}
