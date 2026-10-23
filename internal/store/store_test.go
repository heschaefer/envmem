//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

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

// Sessões, rodando como envmem_app (os privilégios da 00003 bastam).
func TestSessions(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	owner := openStore(t, url)
	if err := owner.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, asAppRole(url))
	u, err := s.CreateFirstSuperadmin(ctx, "admin@empresa.com", "hash-antigo")
	if err != nil {
		t.Fatal(err)
	}

	hash := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Second)
	for b, exp := range map[byte]time.Time{1: future, 2: future, 3: past} {
		if err := s.CreateSession(ctx, hash(b), u.ID, exp); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	if got, err := s.UserBySession(ctx, hash(1)); err != nil || got.ID != u.ID {
		t.Fatalf("UserBySession = %+v, %v", got, err)
	}
	// Sessão vencida, conferida pelo relógio do banco.
	if _, err := s.UserBySession(ctx, hash(3)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sessão vencida: %v, quero ErrNotFound", err)
	}

	// Trocar a senha mantém a sessão atual e revoga as outras.
	if err := s.ChangePassword(ctx, u.ID, "hash-novo", hash(1)); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if got, err := s.UserBySession(ctx, hash(1)); err != nil || got.PasswordHash != "hash-novo" || got.TempPasswordExpiresAt != nil {
		t.Fatalf("sessão atual depois da troca = %+v, %v", got, err)
	}
	if _, err := s.UserBySession(ctx, hash(2)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a outra sessão deveria ter sido revogada: %v", err)
	}

	if err := s.DeleteSession(ctx, hash(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySession(ctx, hash(1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("depois do logout: %v", err)
	}
	// O banco só aceita hash de 32 bytes (SHA-256).
	if err := s.CreateSession(ctx, []byte("curto"), u.ID, future); err == nil {
		t.Fatal("hash de tamanho errado aceito")
	}
}

// Membros, rodando como envmem_app.
func TestMembers(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	if err := openStore(t, url).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, asAppRole(url))
	u, err := s.CreateFirstSuperadmin(ctx, "dev@empresa.com", "h")
	if err != nil {
		t.Fatal(err)
	}
	demo := createProject(t, s, "demo")
	outro := createProject(t, s, "outro")

	if _, err := s.MemberRole(ctx, demo.ID, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("antes de ser membro: %v", err)
	}
	if err := s.SetMember(ctx, demo.ID, u.ID, RoleDesenvolvedor); err != nil {
		t.Fatal(err)
	}
	// SetMember de novo troca o papel (nomear gestor).
	if err := s.SetMember(ctx, demo.ID, u.ID, RoleGestor); err != nil {
		t.Fatal(err)
	}
	if role, err := s.MemberRole(ctx, demo.ID, u.ID); err != nil || role != RoleGestor {
		t.Fatalf("MemberRole = %q, %v", role, err)
	}
	if err := s.SetMember(ctx, outro.ID, u.ID, RoleDesenvolvedor); err != nil {
		t.Fatal(err)
	}

	got, err := s.ProjectsForMember(ctx, u.ID)
	if err != nil || len(got) != 2 || got[0].Name != "demo" || got[0].Role != RoleGestor || got[1].Role != RoleDesenvolvedor {
		t.Fatalf("ProjectsForMember = %+v, %v", got, err)
	}
	// O banco só aceita os dois papéis de projeto.
	if err := s.SetMember(ctx, demo.ID, u.ID, "superadmin"); err == nil {
		t.Fatal("papel de projeto inválido aceito")
	}
	if err := s.SetMember(ctx, "00000000-0000-0000-0000-000000000000", u.ID, RoleGestor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("projeto inexistente: %v", err)
	}
}

// Usuários, rodando como envmem_app.
func TestUserManagement(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	if err := openStore(t, url).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, asAppRole(url))
	root, err := s.CreateFirstSuperadmin(ctx, "root@empresa.com", "h")
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(72 * time.Hour).Truncate(time.Microsecond)

	dev, err := s.CreateUser(ctx, "dev@empresa.com", "", "h-temp", exp)
	if err != nil || dev.GlobalRole != "" || dev.TempPasswordExpiresAt == nil || !dev.TempPasswordExpiresAt.Equal(exp) {
		t.Fatalf("CreateUser = %+v, %v", dev, err)
	}
	if _, err := s.CreateUser(ctx, "dev@empresa.com", "", "h", exp); !errors.Is(err, ErrConflict) {
		t.Fatalf("e-mail repetido: %v", err)
	}
	if got, err := s.UserByID(ctx, dev.ID); err != nil || got.Email != "dev@empresa.com" {
		t.Fatalf("UserByID = %+v, %v", got, err)
	}
	if _, err := s.UserByID(ctx, "nao-e-uuid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UserByID com id inválido: %v", err)
	}
	if list, err := s.ListUsers(ctx); err != nil || len(list) != 2 || list[0].Email != "dev@empresa.com" {
		t.Fatalf("ListUsers = %+v, %v", list, err)
	}

	// Último superadmin não sai.
	if err := s.DeleteUser(ctx, root.ID); !errors.Is(err, ErrLastSuperadmin) {
		t.Fatalf("remover o último superadmin: %v", err)
	}

	// Reset: senha temporária nova e sessões revogadas.
	hash := bytes.Repeat([]byte{7}, 32)
	if err := s.CreateSession(ctx, hash, dev.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetPassword(ctx, dev.ID, "h-novo", exp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySession(ctx, hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a sessão deveria ter sido revogada: %v", err)
	}

	// Remover o usuário leva sessões e participações junto.
	p := createProject(t, s, "demo")
	if err := s.SetMember(ctx, p.ID, dev.ID, RoleDesenvolvedor); err != nil {
		t.Fatal(err)
	}
	if m, err := s.ListMembers(ctx, p.ID); err != nil || len(m) != 1 || m[0].Email != "dev@empresa.com" {
		t.Fatalf("ListMembers = %+v, %v", m, err)
	}
	if err := s.DeleteUser(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.ListMembers(ctx, p.ID); len(m) != 0 {
		t.Fatalf("participação sobrou: %+v", m)
	}
	if err := s.RemoveMember(ctx, p.ID, dev.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RemoveMember de quem não é membro: %v", err)
	}
}

// O reset no servidor (decisão 46) só vale para o único superadmin.
func TestResetLoneSuperadminPassword(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	if err := openStore(t, url).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, asAppRole(url))
	exp := time.Now().Add(72 * time.Hour)
	if _, err := s.CreateFirstSuperadmin(ctx, "root@empresa.com", "h"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "dev@empresa.com", "", "h", exp); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ResetLoneSuperadminPassword(ctx, "dev@empresa.com", "x", exp); !errors.Is(err, ErrNotSuperadmin) {
		t.Fatalf("usuário comum: %v", err)
	}
	if _, err := s.ResetLoneSuperadminPassword(ctx, "ninguem@empresa.com", "x", exp); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inexistente: %v", err)
	}
	u, err := s.ResetLoneSuperadminPassword(ctx, "root@empresa.com", "h-novo", exp)
	if err != nil {
		t.Fatalf("único superadmin: %v", err)
	}
	if got, _ := s.UserByID(ctx, u.ID); got.PasswordHash != "h-novo" || got.TempPasswordExpiresAt == nil {
		t.Fatalf("depois do reset: %+v", got)
	}
	// O reset feito no servidor fica na auditoria, sem autor (fora da API).
	ev, _ := s.ListAudit(ctx, AuditFilter{Limit: 1})
	if len(ev) != 1 || ev[0].Action != "user.password_reset.server" || ev[0].TargetEmail != "root@empresa.com" || ev[0].UserID != "" {
		t.Fatalf("evento do reset = %+v", ev)
	}

	// Com um segundo superadmin, o reset deve ser feito por ele, pela API.
	if _, err := s.CreateUser(ctx, "super2@empresa.com", RoleSuperadmin, "h", exp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetLoneSuperadminPassword(ctx, "root@empresa.com", "x", exp); !errors.Is(err, ErrSuperadminExists) {
		t.Fatalf("com outro superadmin: %v", err)
	}
}

// Lixeira, retenção e versões, rodando como envmem_app.
func TestTrashAndRetention(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	if err := openStore(t, url).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, asAppRole(url))
	p := createProject(t, s, "demo")
	put := func(key, ct string) int {
		t.Helper()
		v, err := s.InsertSecretVersion(ctx, row(p.ID, key, ct))
		if err != nil {
			t.Fatalf("Insert %s: %v", ct, err)
		}
		return v
	}

	// Retenção: 12 versões gravadas, 10 guardadas.
	for i := 1; i <= SecretRetention+2; i++ {
		put("K", "v"+strconv.Itoa(i))
	}
	meta, err := s.SecretsMeta(ctx, p.ID)
	if err != nil || len(meta) != 1 || meta[0].Version != 12 || meta[0].Versions != SecretRetention {
		t.Fatalf("SecretsMeta = %+v, %v", meta, err)
	}
	if _, err := s.SecretVersion(ctx, p.ID, "K", 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("versão 2 deveria ter sido apagada: %v", err)
	}
	if r, err := s.SecretVersion(ctx, p.ID, "K", 0); err != nil || r.Version != 12 || string(r.Ciphertext) != "v12" {
		t.Fatalf("versão atual = %+v, %v", r, err)
	}

	// Lixeira: some do run e da listagem; restaurar devolve.
	if v, err := s.TrashSecret(ctx, p.ID, "K"); err != nil || v != 12 {
		t.Fatalf("TrashSecret = %d, %v", v, err)
	}
	if got, _ := s.LatestSecrets(ctx, p.ID); len(got) != 0 {
		t.Fatalf("o run ainda vê o segredo na lixeira: %+v", got)
	}
	if _, err := s.SecretVersion(ctx, p.ID, "K", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("segredo na lixeira lido: %v", err)
	}
	if trash, err := s.ListTrash(ctx, p.ID); err != nil || len(trash) != 1 || trash[0].Version != 12 {
		t.Fatalf("ListTrash = %+v, %v", trash, err)
	}
	if _, err := s.TrashSecret(ctx, p.ID, "K"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lixeira de novo: %v", err)
	}
	if _, err := s.RestoreSecret(ctx, p.ID, "K"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LatestSecrets(ctx, p.ID); len(got) != 1 {
		t.Fatalf("depois de restaurar: %+v", got)
	}

	// PUT numa chave da lixeira: versão seguinte, fora da lixeira.
	s.TrashSecret(ctx, p.ID, "K")
	if v := put("K", "nova"); v != 13 {
		t.Fatalf("versão depois da lixeira = %d", v)
	}
	if got, _ := s.LatestSecrets(ctx, p.ID); len(got) != 1 || string(got[0].Ciphertext) != "nova" {
		t.Fatalf("run depois do PUT: %+v", got)
	}

	// Exclusão definitiva só do que está na lixeira.
	if _, err := s.PurgeSecret(ctx, p.ID, "K"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purge fora da lixeira: %v", err)
	}
	s.TrashSecret(ctx, p.ID, "K")
	if _, err := s.PurgeSecret(ctx, p.ID, "K"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProject(ctx, "demo"); err != nil {
		t.Fatalf("projeto sem segredos deveria sair: %v", err)
	}
}

// Auditoria e transações, rodando como envmem_app.
func TestAuditAndInTx(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	if err := openStore(t, url).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, asAppRole(url))
	u, _ := s.CreateFirstSuperadmin(ctx, "root@empresa.com", "h")
	p := createProject(t, s, "demo")

	err := s.InsertAudit(ctx,
		AuditEvent{Action: "vault.unseal", RemoteAddr: "10.0.0.5", Result: AuditFailure},
		AuditEvent{UserID: u.ID, UserEmail: u.Email, RemoteAddr: "::1", Action: "secret.run",
			ProjectID: p.ID, ProjectName: "demo", SecretKey: "DB_PASSWORD", SecretVersion: 3, Result: AuditSuccess},
	)
	if err != nil {
		t.Fatalf("InsertAudit: %v", err)
	}
	got, err := s.ListAudit(ctx, AuditFilter{Limit: 10})
	if err != nil || len(got) != 2 {
		t.Fatalf("ListAudit = %+v, %v", got, err)
	}
	// Mais recente primeiro; campos vazios voltam vazios (NULL no banco).
	if got[0].Action != "secret.run" || got[0].SecretVersion != 3 || got[0].RemoteAddr != "::1" || got[0].UserEmail != u.Email {
		t.Errorf("evento = %+v", got[0])
	}
	if got[1].UserID != "" || got[1].ProjectName != "" || got[1].RemoteAddr != "10.0.0.5" {
		t.Errorf("evento sem usuário = %+v", got[1])
	}
	if f, _ := s.ListAudit(ctx, AuditFilter{ProjectName: "demo", Limit: 10}); len(f) != 1 {
		t.Errorf("filtro por projeto: %+v", f)
	}

	// Vários eventos entram juntos ou nenhum entra (um IP inválido derruba
	// o lote inteiro).
	if err := s.InsertAudit(ctx, AuditEvent{Action: "a", Result: AuditSuccess}, AuditEvent{Action: "b", RemoteAddr: "nao-e-ip", Result: AuditSuccess}); err == nil {
		t.Fatal("IP inválido aceito")
	}
	if n, _ := s.ListAudit(ctx, AuditFilter{Limit: 10}); len(n) != 2 {
		t.Fatalf("lote parcial gravado: %d eventos", len(n))
	}

	// InTx: se o evento falha, a alteração é desfeita junto.
	err = s.InTx(ctx, func(tx *Store) error {
		if _, err := tx.CreateProject(ctx, "nao-deveria-ficar"); err != nil {
			return err
		}
		return tx.InsertAudit(ctx, AuditEvent{Action: "x", Result: "resultado-invalido"})
	})
	if err == nil {
		t.Fatal("o evento inválido deveria falhar")
	}
	if _, err := s.ProjectByName(ctx, "nao-deveria-ficar"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a alteração deveria ter sido desfeita: %v", err)
	}
	// E métodos com transação própria funcionam dentro do InTx (savepoint).
	err = s.InTx(ctx, func(tx *Store) error {
		_, err := tx.InsertSecretVersion(ctx, row(p.ID, "K", "c"))
		return err
	})
	if err != nil {
		t.Fatalf("InsertSecretVersion dentro do InTx: %v", err)
	}
}

// O ciclo do MFA no banco, operando como envmem_app: cadastro pendente,
// confirmação, cada passo uma vez só, reset e desafios do login.
func TestMFA(t *testing.T) {
	ctx := context.Background()
	url := tempSchemaURL(t)
	owner := openStore(t, url)
	if err := owner.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, asAppRole(url))
	u, err := s.CreateFirstSuperadmin(ctx, "admin@empresa.com", "hash")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.TOTPByUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sem MFA: %v, quero ErrNotFound", err)
	}
	totp := func(ct string) TOTP {
		return TOTP{UserID: u.ID, Ciphertext: []byte(ct), Nonce: nonce(), WrappedDEK: []byte("dek"), DEKNonce: nonce()}
	}

	// Um cadastro pendente pode ser recomeçado; confirmado, não.
	if err := s.StartTOTP(ctx, totp("primeiro")); err != nil {
		t.Fatal(err)
	}
	if err := s.StartTOTP(ctx, totp("recomeço")); err != nil {
		t.Fatalf("recomeçar cadastro pendente: %v", err)
	}
	got, err := s.TOTPByUser(ctx, u.ID)
	if err != nil || string(got.Ciphertext) != "recomeço" || got.ConfirmedAt != nil {
		t.Fatalf("pendente = %+v, %v", got, err)
	}
	// Pendente não vale para o login: UseTOTPStep recusa.
	if err := s.UseTOTPStep(ctx, u.ID, 100, 10); !errors.Is(err, ErrConflict) {
		t.Errorf("passo com cadastro pendente: %v, quero ErrConflict", err)
	}
	// Código errado no cadastro não conta para a trava.
	if _, err := s.FailTOTP(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("falha com cadastro pendente: %v, quero ErrNotFound", err)
	}
	if err := s.ConfirmTOTP(ctx, u.ID, 100); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(ctx, u.ID, 101); !errors.Is(err, ErrConflict) {
		t.Errorf("confirmar duas vezes: %v, quero ErrConflict", err)
	}
	if err := s.StartTOTP(ctx, totp("troca")); !errors.Is(err, ErrConflict) {
		t.Errorf("trocar um cadastro confirmado: %v, quero ErrConflict", err)
	}

	// Cada passo vale uma vez: o da confirmação já conta como usado.
	for step, want := range map[int64]error{100: ErrConflict, 99: ErrConflict, 101: nil} {
		if err := s.UseTOTPStep(ctx, u.ID, step, 10); !errors.Is(err, want) {
			t.Errorf("UseTOTPStep(%d) = %v, quero %v", step, err, want)
		}
	}
	if err := s.UseTOTPStep(ctx, u.ID, 101, 10); !errors.Is(err, ErrConflict) {
		t.Error("o mesmo passo foi aceito duas vezes")
	}

	// Falhas seguidas: um código certo zera a contagem, mas, travado (no
	// limite), nem um código certo passa.
	for want := 1; want <= 3; want++ {
		if n, err := s.FailTOTP(ctx, u.ID); err != nil || n != want {
			t.Fatalf("FailTOTP = %d, %v; quero %d", n, err, want)
		}
	}
	if err := s.UseTOTPStep(ctx, u.ID, 102, 3); !errors.Is(err, ErrConflict) {
		t.Errorf("código certo com o MFA travado: %v, quero ErrConflict", err)
	}
	if err := s.UseTOTPStep(ctx, u.ID, 102, 10); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.TOTPByUser(ctx, u.ID); got.Failures != 0 || got.LastStep != 102 {
		t.Errorf("depois do código certo: falhas %d, passo %d", got.Failures, got.LastStep)
	}

	// Gestor de algum projeto precisa de MFA; membro só desenvolvedor, não.
	p := createProject(t, s, "demo")
	dev, err := s.CreateUser(ctx, "dev@empresa.com", "", "hash", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMember(ctx, p.ID, dev.ID, "desenvolvedor"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ManagesAnyProject(ctx, dev.ID); err != nil || ok {
		t.Errorf("desenvolvedor: ManagesAnyProject = %v, %v", ok, err)
	}
	if err := s.SetMember(ctx, p.ID, dev.ID, "gestor"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ManagesAnyProject(ctx, dev.ID); err != nil || !ok {
		t.Errorf("gestor: ManagesAnyProject = %v, %v", ok, err)
	}

	// Desafios: só o hash, validade pelo relógio do banco, contagem de
	// falhas e uso único.
	hash := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	if err := s.CreateMFAChallenge(ctx, hash(1), u.ID, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateMFAChallenge(ctx, hash(2), u.ID, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if id, n, err := s.MFAChallenge(ctx, hash(1)); err != nil || id != u.ID || n != 0 {
		t.Fatalf("MFAChallenge = %q, %d, %v", id, n, err)
	}
	if _, _, err := s.MFAChallenge(ctx, hash(2)); !errors.Is(err, ErrNotFound) {
		t.Errorf("desafio vencido: %v, quero ErrNotFound", err)
	}
	for want := 1; want <= 2; want++ {
		if n, err := s.FailMFAChallenge(ctx, hash(1)); err != nil || n != want {
			t.Errorf("FailMFAChallenge = %d, %v; quero %d", n, err, want)
		}
	}
	if err := s.DeleteMFAChallenge(ctx, hash(1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MFAChallenge(ctx, hash(1)); !errors.Is(err, ErrNotFound) {
		t.Errorf("desafio usado: %v, quero ErrNotFound", err)
	}

	// Reset: apaga o MFA, os desafios e as sessões do usuário.
	if err := s.CreateMFAChallenge(ctx, hash(3), u.ID, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, hash(4), u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetMFA(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TOTPByUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("MFA depois do reset: %v", err)
	}
	if _, _, err := s.MFAChallenge(ctx, hash(3)); !errors.Is(err, ErrNotFound) {
		t.Errorf("desafio depois do reset: %v", err)
	}
	if _, err := s.UserBySession(ctx, hash(4)); !errors.Is(err, ErrNotFound) {
		t.Errorf("sessão depois do reset: %v", err)
	}
	if err := s.ResetMFA(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("reset sem MFA: %v, quero ErrNotFound", err)
	}
	if err := s.ResetMFA(ctx, "nao-e-uuid"); !errors.Is(err, ErrNotFound) {
		t.Errorf("id inválido: %v, quero ErrNotFound", err)
	}

	// Reset no servidor: só o único superadmin, e só com MFA.
	if _, err := s.ResetLoneSuperadminMFA(ctx, "admin@empresa.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("superadmin sem MFA: %v, quero ErrNotFound", err)
	}
	if err := s.StartTOTP(ctx, totp("de novo")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetLoneSuperadminMFA(ctx, "dev@empresa.com"); !errors.Is(err, ErrNotSuperadmin) {
		t.Errorf("não superadmin: %v, quero ErrNotSuperadmin", err)
	}
	if got, err := s.ResetLoneSuperadminMFA(ctx, "admin@empresa.com"); err != nil || got.ID != u.ID {
		t.Fatalf("ResetLoneSuperadminMFA = %+v, %v", got, err)
	}
	if err := s.StartTOTP(ctx, totp("outra vez")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "outro@empresa.com", RoleSuperadmin, "hash", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetLoneSuperadminMFA(ctx, "admin@empresa.com"); !errors.Is(err, ErrSuperadminExists) {
		t.Errorf("com outro superadmin: %v, quero ErrSuperadminExists", err)
	}
}
