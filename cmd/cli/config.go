package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/heschaefer/envmem/internal/client"
)

// defaultServer é o endereço usado quando não há --servidor nem
// config.json (antes do primeiro login).
const defaultServer = "https://localhost:8080"

// cliConfig é o conteúdo de ~/.config/envmem/config.json (decisão 38),
// gravado pelo "envmem login". Não guarda segredos nem o token, que fica
// em arquivo próprio (decisão 4).
type cliConfig struct {
	Server string `json:"server"`
	CA     string `json:"ca,omitempty"` // caminho absoluto do ca.crt; vazio usa as CAs do sistema
}

func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// loadConfig lê o config.json. Não existir não é erro: devolve a
// configuração vazia.
//
// O arquivo não é secreto, mas quem consegue alterá-lo aponta o CLI para
// outro servidor e outra CA, e o CLI entregaria o token a esse servidor.
// Por isso, como o ssh faz com o ~/.ssh/config, recusa um arquivo em que
// outros usuários possam escrever.
func loadConfig() (cliConfig, error) {
	var cfg cliConfig
	path, err := configPath()
	if err != nil {
		return cfg, err
	}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return cfg, fmt.Errorf("o arquivo %s pode ser alterado por outros usuários (permissão %o); "+
			"corrija com chmod 600", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("o arquivo %s é inválido (%v); corrija ou apague e rode envmem login", path, err)
	}
	return cfg, nil
}

// saveConfig grava o config.json com permissão 600, do mesmo jeito que o
// token (ver writePrivateFile).
func saveConfig(cfg cliConfig) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateFile(path, append(data, '\n')); err != nil {
		return fmt.Errorf("gravar %s: %w", path, err)
	}
	return nil
}

// connFlags são as flags de conexão com o servidor, comuns a todos os
// subcomandos. Os valores vêm do config.json; as flags, quando informadas,
// têm precedência (decisões 24 e 38).
type connFlags struct {
	fs       *flag.FlagSet
	servidor string
	ca       string
}

func addConnFlags(fs *flag.FlagSet) *connFlags {
	f := &connFlags{fs: fs}
	fs.StringVar(&f.servidor, "servidor", "", "endereço do envmem-server (padrão: o do config.json, ou "+defaultServer+")")
	fs.StringVar(&f.ca, "ca", "", "certificado da CA do envmem (ca.crt) (padrão: o do config.json; vazio usa as CAs do sistema)")
	return f
}

// resolve combina, nesta ordem de precedência, as flags informadas, o
// config.json e o endereço padrão. Só conta como informada a flag que
// apareceu na linha de comando (fs.Visit), para que um --ca vazio possa
// desligar a CA do config.json e voltar às CAs do sistema.
func (f *connFlags) resolve() (cliConfig, error) {
	cfg, err := loadConfig()
	if err != nil {
		return cfg, err
	}
	f.fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "servidor":
			cfg.Server = f.servidor
		case "ca":
			cfg.CA = f.ca
		}
	})
	if cfg.Server == "" {
		cfg.Server = defaultServer
	}
	return cfg, nil
}

// client cria o cliente da API com a configuração resolvida.
func (f *connFlags) client() (*client.Client, error) {
	cfg, err := f.resolve()
	if err != nil {
		return nil, err
	}
	return newClient(cfg)
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

func newClient(cfg cliConfig) (*client.Client, error) {
	var roots *x509.CertPool
	if cfg.CA != "" {
		var err error
		if roots, err = client.LoadCA(cfg.CA); err != nil {
			return nil, err
		}
	}
	return client.New(cfg.Server, roots)
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
