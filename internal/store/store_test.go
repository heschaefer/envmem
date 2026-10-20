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

func row(projectID, key, ciphertext string) SecretRow {
	return SecretRow{
		ProjectID: projectID, Key: key,
		Ciphertext: []byte(ciphertext), Nonce: nonce(),
		WrappedDEK: []byte("dek"), DEKNonce: nonce(),
	}
}

func createProject(t *testing.T, s *Store, name string) Project {
	t.Helper()
	p, err := s.CreateProject(context.Background(), name)
	if err != nil {
		t.Fatalf("CreateProject(%q): %v", name, err)
	}
	return p
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("segunda Migrate: %v", err)
	}
}

func TestProjects(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	homo := createProject(t, s, "app-homo")
	createProject(t, s, "app-prod")
	if homo.ID == "" {
		t.Fatal("projeto criado sem id")
	}
	if _, err := s.CreateProject(ctx, "app-homo"); !errors.Is(err, ErrConflict) {
		t.Fatalf("nome repetido: %v, quero ErrConflict", err)
	}

	got, err := s.ProjectByName(ctx, "app-homo")
	if err != nil || got.ID != homo.ID {
		t.Fatalf("ProjectByName = %+v, %v; quero id %s", got, err, homo.ID)
	}
	if _, err := s.ProjectByName(ctx, "nao-existe"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ProjectByName inexistente: %v, quero ErrNotFound", err)
	}

	list, err := s.ListProjects(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "app-homo" || list[1].Name != "app-prod" {
		t.Fatalf("ListProjects = %+v, %v", list, err)
	}

	if err := s.DeleteProject(ctx, "app-prod"); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	if err := s.DeleteProject(ctx, "app-prod"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteProject de novo: %v, quero ErrNotFound", err)
	}
}

// O CHECK do banco recusa nomes fora do formato, mesmo que a API deixe
// passar por engano.
func TestProjectNameIsChecked(t *testing.T) {
	s := newTestStore(t)
	for _, name := range []string{"", "App", "-x", "a b", "a/b", strings.Repeat("a", 64)} {
		if _, err := s.CreateProject(context.Background(), name); err == nil {
			t.Errorf("CreateProject(%q): esperava erro", name)
		}
	}
}

func TestDeleteProjectWithSecrets(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p := createProject(t, s, "demo")
	if _, err := s.InsertSecretVersion(ctx, row(p.ID, "K", "c")); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteProject(ctx, "demo"); !errors.Is(err, ErrProjectNotEmpty) {
		t.Fatalf("DeleteProject: %v, quero ErrProjectNotEmpty", err)
	}
	if _, err := s.ProjectByName(ctx, "demo"); err != nil {
		t.Fatalf("o projeto deveria continuar existindo: %v", err)
	}
}

func TestSecretVersions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	demo := createProject(t, s, "demo")
	outro := createProject(t, s, "outro")

	for i, c := range []string{"v1", "v2", "v3"} {
		v, err := s.InsertSecretVersion(ctx, row(demo.ID, "DB_PASSWORD", c))
		if err != nil {
			t.Fatalf("Insert %s: %v", c, err)
		}
		if v != i+1 {
			t.Errorf("versão = %d, quero %d", v, i+1)
		}
	}
	if _, err := s.InsertSecretVersion(ctx, row(demo.ID, "API_KEY", "a1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertSecretVersion(ctx, row(outro.ID, "DB_PASSWORD", "x1")); err != nil {
		t.Fatal(err)
	}

	got, err := s.LatestSecrets(ctx, demo.ID)
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
	p := createProject(t, s, "vazio")
	got, err := s.LatestSecrets(context.Background(), p.ID)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v; quero lista vazia", got, err)
	}
}

// Um segredo num projeto que não existe (por exemplo, apagado entre a
// consulta e a gravação) é recusado pela chave estrangeira.
func TestInsertSecretUnknownProject(t *testing.T) {
	s := newTestStore(t)
	p := createProject(t, s, "efemero")
	if err := s.DeleteProject(context.Background(), "efemero"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertSecretVersion(context.Background(), row(p.ID, "K", "c")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Insert em projeto apagado: %v, quero ErrNotFound", err)
	}
}

func TestNonceLengthIsChecked(t *testing.T) {
	s := newTestStore(t)
	p := createProject(t, s, "demo")
	r := row(p.ID, "K", "c")
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
