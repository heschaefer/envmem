package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useTempConfig aponta o ~/.config do teste para uma pasta temporária.
func useTempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "envmem")
}

func TestTokenFile(t *testing.T) {
	dir := useTempConfig(t)

	if _, err := loadToken(); !errors.Is(err, errNoSession) {
		t.Fatalf("sem arquivo: %v, quero errNoSession", err)
	}
	if err := saveToken("token-de-teste"); err != nil {
		t.Fatalf("saveToken: %v", err)
	}

	// Pasta 700 e arquivo 600: só o próprio usuário acessa.
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "token"): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: permissão %o, quero %o", path, got, want)
		}
	}
	// Nenhum arquivo temporário sobra na pasta.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("arquivos na pasta: %d, quero só o token", len(entries))
	}

	if got, err := loadToken(); err != nil || got != "token-de-teste" {
		t.Fatalf("loadToken = %q, %v", got, err)
	}

	if err := deleteToken(); err != nil {
		t.Fatal(err)
	}
	if err := deleteToken(); err != nil {
		t.Fatalf("apagar duas vezes não é erro: %v", err)
	}
	if _, err := loadToken(); !errors.Is(err, errNoSession) {
		t.Fatalf("depois de apagar: %v", err)
	}
}

// Como o ssh com chaves privadas: um token legível por outros usuários é
// recusado, mas o logout ainda consegue lê-lo para revogar.
func TestLoadTokenRefusesOpenPermissions(t *testing.T) {
	dir := useTempConfig(t)
	if err := saveToken("token-exposto"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "token")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadToken(); err == nil || !strings.Contains(err.Error(), "outros usuários") {
		t.Fatalf("loadToken com 644: %v, esperava recusa", err)
	}
	if got, err := readToken(path); err != nil || got != "token-exposto" {
		t.Fatalf("readToken (logout) = %q, %v", got, err)
	}
}
