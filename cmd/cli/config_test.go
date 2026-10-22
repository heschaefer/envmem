package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseConn monta as flags de conexão como um subcomando faria e lê args.
func parseConn(t *testing.T, args ...string) *connFlags {
	t.Helper()
	fs := flag.NewFlagSet("teste", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	conn := addConnFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestConfigFile(t *testing.T) {
	dir := useTempConfig(t)

	// Sem config.json nem flags: o endereço padrão e as CAs do sistema.
	cfg, err := parseConn(t).resolve()
	if err != nil || cfg != (cliConfig{Server: defaultServer}) {
		t.Fatalf("sem arquivo: %+v, %v", cfg, err)
	}

	saved := cliConfig{Server: "https://envmem.empresa.com:8443", CA: "/etc/envmem/ca.crt"}
	if err := saveConfig(saved); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("permissão %o, quero 600", got)
	}

	tests := []struct {
		name string
		args []string
		want cliConfig
	}{
		{"só o arquivo", nil, saved},
		{"--servidor sobrescreve", []string{"--servidor", "https://outro:8080"},
			cliConfig{Server: "https://outro:8080", CA: saved.CA}},
		{"--ca sobrescreve", []string{"--ca", "certs/ca.crt"},
			cliConfig{Server: saved.Server, CA: "certs/ca.crt"}},
		// Informar --ca vazio é diferente de não informar: volta às CAs do
		// sistema, mesmo com uma CA no arquivo.
		{"--ca vazio desliga a CA do arquivo", []string{"--ca", ""},
			cliConfig{Server: saved.Server}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseConn(t, tt.args...).resolve()
			if err != nil || got != tt.want {
				t.Errorf("resolve = %+v, %v; quero %+v", got, err, tt.want)
			}
		})
	}
}

// Quem pode alterar o config.json aponta o CLI para outro servidor, que
// receberia o token: um arquivo gravável por outros usuários é recusado.
func TestConfigRefusesWritableByOthers(t *testing.T) {
	dir := useTempConfig(t)
	if err := saveConfig(cliConfig{Server: "https://localhost:8080"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")

	// Legível por todos não é problema: o arquivo não tem segredo.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err != nil {
		t.Errorf("com 644: %v", err)
	}

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConn(t).client(); err == nil || !strings.Contains(err.Error(), "outros usuários") {
		t.Errorf("com 666: %v, esperava recusa", err)
	}
}

func TestConfigInvalid(t *testing.T) {
	dir := useTempConfig(t)
	if err := writePrivateFile(filepath.Join(dir, "config.json"), []byte("{não é json")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "inválido") {
		t.Errorf("JSON inválido: %v, esperava erro", err)
	}
}
