// Package config lê a configuração do envmem-server a partir de variáveis de
// ambiente, com flags de linha de comando que as sobrescrevem.
package config

import (
	"errors"
	"flag"
	"io"
	"os"
)

// Server é a configuração do envmem-server.
type Server struct {
	// ListenAddr é o endereço onde o servidor escuta, como ":8080".
	ListenAddr string
	// DatabaseURL é a URL de conexão do PostgreSQL. Vem só da variável
	// DATABASE_URL, sem flag: ela contém a senha do banco, e argumentos de
	// linha de comando ficam visíveis para outros usuários no "ps".
	DatabaseURL string
}

// LoadServer lê as variáveis de ambiente e aplica as flags de args por cima.
// Precedência: flag > variável de ambiente > valor padrão.
func LoadServer(args []string, stderr io.Writer) (Server, error) {
	cfg := Server{
		ListenAddr:  envOr("ENVMEM_LISTEN_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
	}

	fs := flag.NewFlagSet("envmem-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "endereço de escuta (ou ENVMEM_LISTEN_ADDR)")
	if err := fs.Parse(args); err != nil {
		return Server{}, err
	}
	if cfg.DatabaseURL == "" {
		return Server{}, errors.New("DATABASE_URL não definida")
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}
