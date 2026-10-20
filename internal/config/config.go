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
	// TLSCertFile e TLSKeyFile são o certificado do servidor e a chave
	// privada dele, em PEM (gerados por scripts/gen-certs.sh).
	TLSCertFile string
	TLSKeyFile  string
}

// LoadServer lê as variáveis de ambiente e aplica as flags de args por cima.
// Precedência: flag > variável de ambiente > valor padrão.
func LoadServer(args []string, stderr io.Writer) (Server, error) {
	cfg := Server{
		ListenAddr:  envOr("ENVMEM_LISTEN_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		TLSCertFile: envOr("ENVMEM_TLS_CERT", "certs/server.crt"),
		TLSKeyFile:  envOr("ENVMEM_TLS_KEY", "certs/server.key"),
	}

	fs := flag.NewFlagSet("envmem-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "endereço de escuta (ou ENVMEM_LISTEN_ADDR)")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert", cfg.TLSCertFile, "certificado TLS do servidor, em PEM (ou ENVMEM_TLS_CERT)")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key", cfg.TLSKeyFile, "chave privada TLS do servidor, em PEM (ou ENVMEM_TLS_KEY)")
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
