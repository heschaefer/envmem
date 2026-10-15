//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// newTestStore abre o banco num schema temporário, aplica as migrações e
// apaga o schema no fim do teste. Assim os testes não tocam nas tabelas da
// demonstração.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL não definida")
	}

	schema := "test_" + strings.ToLower(rand.Text()[:10])
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("conectar: %v", err)
	}
	defer admin.Close(ctx)
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		t.Fatalf("criar schema: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), url)
		if err != nil {
			t.Errorf("limpar schema: %v", err)
			return
		}
		defer c.Close(context.Background())
		c.Exec(context.Background(), "DROP SCHEMA "+ident+" CASCADE")
	})

	// O pgx repassa parâmetros desconhecidos da URL ao servidor; search_path
	// faz todas as tabelas (inclusive a do goose) nascerem no schema novo.
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	s, err := Open(ctx, url+sep+"search_path="+schema)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func nonce() []byte { return bytes.Repeat([]byte{1}, 12) }

func row(project, key, ciphertext string) SecretRow {
	return SecretRow{
		Project: project, Key: key,
		Ciphertext: []byte(ciphertext), Nonce: nonce(),
		WrappedDEK: []byte("dek"), DEKNonce: nonce(),
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("segunda Migrate: %v", err)
	}
}

func TestSecretVersions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i, c := range []string{"v1", "v2", "v3"} {
		v, err := s.InsertSecretVersion(ctx, row("demo", "DB_PASSWORD", c))
		if err != nil {
			t.Fatalf("Insert %s: %v", c, err)
		}
		if v != i+1 {
			t.Errorf("versão = %d, quero %d", v, i+1)
		}
	}
	if _, err := s.InsertSecretVersion(ctx, row("demo", "API_KEY", "a1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertSecretVersion(ctx, row("outro", "DB_PASSWORD", "x1")); err != nil {
		t.Fatal(err)
	}

	got, err := s.LatestSecrets(ctx, "demo")
	if err != nil {
		t.Fatalf("LatestSecrets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, quero 2 (só o projeto demo, uma linha por chave)", len(got))
	}
	// Ordem por chave: API_KEY, depois DB_PASSWORD.
	if got[0].Key != "API_KEY" || got[0].Version != 1 || string(got[0].Ciphertext) != "a1" {
		t.Errorf("API_KEY inesperado: %+v", got[0])
	}
	if got[1].Key != "DB_PASSWORD" || got[1].Version != 3 || string(got[1].Ciphertext) != "v3" {
		t.Errorf("DB_PASSWORD deveria estar na versão 3: %+v", got[1])
	}
}

func TestLatestSecretsEmpty(t *testing.T) {
	s := newTestStore(t)
	got, err := s.LatestSecrets(context.Background(), "nao-existe")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v; quero lista vazia", got, err)
	}
}

func TestNonceLengthIsChecked(t *testing.T) {
	s := newTestStore(t)
	r := row("demo", "K", "c")
	r.Nonce = []byte("curto")
	if _, err := s.InsertSecretVersion(context.Background(), r); err == nil {
		t.Fatal("esperava erro: nonce com tamanho diferente de 12")
	}
}

func TestVaultMeta(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.GetVaultMeta(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetVaultMeta antes do primeiro unseal: %v, quero ErrNotFound", err)
	}

	first := VaultMeta{CheckCiphertext: []byte("primeiro"), CheckNonce: nonce()}
	if ok, err := s.InsertVaultMeta(ctx, first); err != nil || !ok {
		t.Fatalf("primeiro InsertVaultMeta = %v, %v; quero true", ok, err)
	}
	second := VaultMeta{CheckCiphertext: []byte("segundo"), CheckNonce: nonce()}
	if ok, err := s.InsertVaultMeta(ctx, second); err != nil || ok {
		t.Fatalf("segundo InsertVaultMeta = %v, %v; quero false (não sobrescreve)", ok, err)
	}

	got, err := s.GetVaultMeta(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.CheckCiphertext) != "primeiro" {
		t.Errorf("valor de verificação foi sobrescrito: %q", got.CheckCiphertext)
	}
}
