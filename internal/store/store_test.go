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

// ensureAppRoleSQL cria o envmem_app (sem login) se ainda não existir, para
// que as migrações consigam dar privilégios a ele. Em desenvolvimento, quem
// cria o usuário de verdade é o scripts/db-init. A exceção cobre dois
// pacotes de teste criando ao mesmo tempo.
const ensureAppRoleSQL = `
DO $$
BEGIN
    CREATE ROLE envmem_app NOLOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END
$$`

// tempSchemaURL cria um schema temporário e devolve a URL do banco, como
// dono, apontando para ele. O schema é apagado no fim do teste. Assim os
// testes não tocam nas tabelas da demonstração.
func tempSchemaURL(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("DATABASE_MIGRATE_URL")
	if url == "" {
		t.Skip("DATABASE_MIGRATE_URL não definida (URL do usuário dono do banco)")
	}

	schema := "test_" + strings.ToLower(rand.Text()[:10])
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("conectar: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, ensureAppRoleSQL); err != nil {
		t.Fatalf("criar envmem_app: %v", err)
	}
	ident := pgx.Identifier{schema}.Sanitize()
	// O envmem_app precisa de USAGE para enxergar as tabelas do schema.
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident+"; GRANT USAGE ON SCHEMA "+ident+" TO envmem_app"); err != nil {
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
	return url + sep + "search_path=" + schema
}

// asAppRole devolve a URL com a sessão rodando como envmem_app (o "role"
// vai como parâmetro de início de sessão), sem precisar da senha dele.
func asAppRole(url string) string {
	return url + "&options=-c%20role%3Denvmem_app"
}

func openStore(t *testing.T, url string) *Store {
	t.Helper()
	s, err := Open(context.Background(), url)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// newTestStore abre, como dono, um schema temporário já migrado.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := openStore(t, tempSchemaURL(t))
	if err := s.Migrate(context.Background()); err != nil {
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

func TestCheckMigrated(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	owner := openStore(t, url)

	// Banco nunca migrado (sem a tabela do goose) conta como pendente.
	if err := owner.CheckMigrated(ctx); !errors.Is(err, ErrPendingMigrations) {
		t.Fatalf("antes do migrate: %v, quero ErrPendingMigrations", err)
	}
	if err := owner.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// O envmem_app consegue conferir: só lê a tabela de controle do goose.
	if err := openStore(t, asAppRole(url)).CheckMigrated(ctx); err != nil {
		t.Fatalf("depois do migrate, como envmem_app: %v", err)
	}

	// Banco anterior à 00003: o envmem_app ainda não pode ler a tabela do
	// goose, e isso também conta como pendente.
	if _, err := owner.pool.Exec(ctx, `REVOKE SELECT ON goose_db_version FROM envmem_app`); err != nil {
		t.Fatal(err)
	}
	if err := openStore(t, asAppRole(url)).CheckMigrated(ctx); !errors.Is(err, ErrPendingMigrations) {
		t.Fatalf("sem SELECT na tabela do goose: %v, quero ErrPendingMigrations", err)
	}

	// Simula um binário mais novo que o banco: a última migração some do
	// registro do goose.
	if _, err := owner.pool.Exec(ctx, `DELETE FROM goose_db_version WHERE version_id = (SELECT max(version_id) FROM goose_db_version)`); err != nil {
		t.Fatal(err)
	}
	if err := owner.CheckMigrated(ctx); !errors.Is(err, ErrPendingMigrations) {
		t.Fatalf("com migração faltando: %v, quero ErrPendingMigrations", err)
	}
}

// O servidor só sobe com o usuário restrito: o dono das tabelas (aqui,
// também superusuário) é recusado.
func TestCheckRestricted(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	owner := openStore(t, url)
	if err := owner.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	if err := owner.CheckRestricted(ctx); !errors.Is(err, ErrPrivilegedUser) {
		t.Fatalf("como dono: %v, quero ErrPrivilegedUser", err)
	}
	if err := openStore(t, asAppRole(url)).CheckRestricted(ctx); err != nil {
		t.Fatalf("como envmem_app: %v", err)
	}
}

// A garantia da auditoria fica no banco, não no código: o envmem_app insere
// e lê eventos, mas não consegue alterar, apagar nem truncar, nem com SQL
// escrito à mão.
func TestAppRoleCannotTamperWithAudit(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	if err := openStore(t, url).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	app, err := pgx.Connect(ctx, asAppRole(url))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close(ctx)

	if _, err := app.Exec(ctx, `INSERT INTO audit_events (action, result) VALUES ('teste', 'success')`); err != nil {
		t.Fatalf("INSERT na auditoria deveria funcionar: %v", err)
	}
	var n int
	if err := app.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("SELECT na auditoria = %d, %v", n, err)
	}

	for _, q := range []string{
		`UPDATE audit_events SET result = 'denied'`,
		`DELETE FROM audit_events`,
		`TRUNCATE audit_events`,
		`DROP TABLE audit_events`,
		`ALTER TABLE audit_events DISABLE TRIGGER ALL`,
		`TRUNCATE secrets`,
		`DROP TABLE secrets`,
	} {
		if _, err := app.Exec(ctx, q); !isPermissionDenied(err) {
			t.Errorf("%s: erro = %v, quero permissão negada", q, err)
		}
	}

	// Tentar se dar o privilégio não dá erro no PostgreSQL: sem permissão de
	// repassá-lo, o GRANT só emite um aviso e não concede nada. Por isso o
	// que se confere é o efeito: o DELETE continua negado.
	app.Exec(ctx, `GRANT DELETE ON audit_events TO envmem_app`)
	if _, err := app.Exec(ctx, `DELETE FROM audit_events`); !isPermissionDenied(err) {
		t.Errorf("DELETE depois do GRANT: erro = %v, quero permissão negada", err)
	}
}

// isPermissionDenied diz se err é recusa de privilégio (42501) ou de dono
// (o PostgreSQL usa 42501 para os dois casos).
func isPermissionDenied(err error) bool {
	return hasCode(err, "42501")
}

func TestFirstSuperadmin(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, err := s.CreateFirstSuperadmin(ctx, "admin@empresa.com", "$argon2id$hash")
	if err != nil {
		t.Fatalf("CreateFirstSuperadmin: %v", err)
	}
	if u.ID == "" || u.GlobalRole != RoleSuperadmin || u.TempPasswordExpiresAt != nil {
		t.Fatalf("usuário criado = %+v", u)
	}
	// Só o primeiro: com um superadmin existente, o comando não cria outro.
	if _, err := s.CreateFirstSuperadmin(ctx, "outro@empresa.com", "h"); !errors.Is(err, ErrSuperadminExists) {
		t.Fatalf("segundo superadmin: %v, quero ErrSuperadminExists", err)
	}

	got, err := s.UserByEmail(ctx, "admin@empresa.com")
	if err != nil || got.ID != u.ID || got.PasswordHash != "$argon2id$hash" {
		t.Fatalf("UserByEmail = %+v, %v", got, err)
	}
	if _, err := s.UserByEmail(ctx, "ninguem@empresa.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UserByEmail inexistente: %v, quero ErrNotFound", err)
	}
}

// O banco só aceita e-mail já normalizado (minúsculas), mesmo que a
// aplicação esqueça de normalizar.
func TestUserEmailIsChecked(t *testing.T) {
	s := newTestStore(t)
	for _, email := range []string{"Admin@Empresa.com", "sem-arroba", "@empresa.com"} {
		if _, err := s.CreateFirstSuperadmin(context.Background(), email, "h"); err == nil || errors.Is(err, ErrSuperadminExists) {
			t.Errorf("CreateFirstSuperadmin(%q): %v, esperava recusa do CHECK", email, err)
		}
	}
}
