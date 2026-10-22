//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/heschaefer/envmem/internal/api"
	"github.com/heschaefer/envmem/internal/store"
	"github.com/heschaefer/envmem/internal/vault"
)

// e2eEnv faz o binário de teste, quando reexecutado, agir como o envmem
// com os argumentos de linha de comando em ENVMEM_E2E_ARGS.
const e2eEnv = "ENVMEM_E2E_ARGS"

// TestEndToEnd percorre o roteiro da demonstração com as peças reais:
// PostgreSQL (schema temporário), cofre, roteador, cliente HTTP e o
// "envmem run" fazendo syscall.Exec.
func TestEndToEnd(t *testing.T) {
	if args := os.Getenv(e2eEnv); args != "" {
		os.Exit(run(strings.Split(args, "\x1f")))
	}

	ctx := context.Background()
	// Como no servidor real (decisão 42): migra como dono e opera como
	// envmem_app. Se faltar algum privilégio na migração, este teste falha.
	dbURL := tempSchemaURL(t)
	owner, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	if err := owner.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, dbURL+"&options=-c%20role%3Denvmem_app")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.CheckRestricted(ctx); err != nil {
		t.Fatalf("o roteador deveria rodar com o usuário restrito: %v", err)
	}

	// startServer simula uma subida do envmem-server: cofre novo (selado),
	// mesmo banco, só TLS 1.3. hc é um cliente HTTP que confia no
	// certificado do servidor, para os passos feitos "com curl".
	var hc *http.Client
	ca := filepath.Join(t.TempDir(), "ca.crt")
	startServer := func() string {
		srv := httptest.NewUnstartedServer(api.NewRouter(slog.New(slog.DiscardHandler), st, vault.New()))
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		hc = srv.Client()
		// O certificado de teste é autoassinado: ele mesmo faz o papel do
		// ca.crt que o CLI recebe em --ca.
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		if err := os.WriteFile(ca, pemCert, 0o644); err != nil {
			t.Fatal(err)
		}
		return srv.URL
	}
	key := vault.EncodeKey(vault.GenerateKey())
	const value = "S3nh@-de-ponta-a-ponta"

	// 1. Sobe selado: GET de segredos devolve 503.
	url := startServer()
	wantStatus(t, "GET selado", http.StatusServiceUnavailable,
		request(t, hc, http.MethodGet, url+"/v1/projects/demo/secrets", ""))

	// 2. Unseal com a chave gerada.
	wantStatus(t, "unseal", http.StatusOK,
		request(t, hc, http.MethodPost, url+"/v1/unseal", `{"key":"`+key+`"}`))

	// 3. Cria o projeto demo pelo CLI e grava o segredo DB_PASSWORD nele.
	if _, stdout, _ := runEnvmem(t, "projects", "create", "--servidor", url, "--ca", ca, "demo"); stdout != "projeto demo criado\n" {
		t.Errorf("projects create: stdout = %q", stdout)
	}
	if _, stdout, _ := runEnvmem(t, "projects", "list", "--servidor", url, "--ca", ca); stdout != "demo\n" {
		t.Errorf("projects list: stdout = %q, quero %q", stdout, "demo\n")
	}
	wantStatus(t, "PUT", http.StatusCreated,
		request(t, hc, http.MethodPut, url+"/v1/projects/demo/secrets/DB_PASSWORD", `{"value":"`+value+`"}`))

	// 4. No banco, o valor está ilegível.
	assertNoPlaintextInDB(t, dbURL, value)

	// 5. envmem run: o comando recebe a senha, no mesmo PID que o envmem
	// imprimiu antes do exec.
	pid, stdout, stderr := runEnvmem(t, "run", "--verbose", "--servidor", url, "--ca", ca, "--projeto", "demo",
		"--", "sh", "-c", `echo "$$ $DB_PASSWORD"`)
	if want := fmt.Sprintf("envmem: pid %d,", pid); !strings.HasPrefix(stderr, want) {
		t.Errorf("stderr = %q, quero começar com %q", stderr, want)
	}
	if want := fmt.Sprintf("%d %s\n", pid, value); stdout != want {
		t.Errorf("stdout = %q, quero %q", stdout, want)
	}

	// 6. Reinício: volta selado; só a mesma chave abre, e o segredo continua lá.
	url = startServer()
	wantStatus(t, "GET depois do reinício", http.StatusServiceUnavailable,
		request(t, hc, http.MethodGet, url+"/v1/projects/demo/secrets", ""))
	wantStatus(t, "unseal com outra chave", http.StatusUnauthorized,
		request(t, hc, http.MethodPost, url+"/v1/unseal", `{"key":"`+vault.EncodeKey(vault.GenerateKey())+`"}`))
	wantStatus(t, "unseal com a chave certa", http.StatusOK,
		request(t, hc, http.MethodPost, url+"/v1/unseal", `{"key":"`+key+`"}`))
	_, stdout, _ = runEnvmem(t, "run", "--servidor", url, "--ca", ca, "--projeto", "demo", "--", "sh", "-c", `echo "$DB_PASSWORD"`)
	if stdout != value+"\n" {
		t.Errorf("depois do reinício, stdout = %q, quero %q", stdout, value+"\n")
	}

	// 7. DELETE pelo CLI: projeto com segredos é recusado (409) e continua
	// inteiro; projeto vazio é removido; projeto inexistente dá 404.
	// projects monta "projects AÇÃO --servidor URL --ca CA [NOME]": as
	// flags vêm antes do nome.
	projects := func(action string, name ...string) []string {
		return append([]string{"projects", action, "--servidor", url, "--ca", ca}, name...)
	}
	_, _, stderr, code := execEnvmem(t, projects("delete", "demo")...)
	if code != 1 || !strings.Contains(stderr, "409 (project_not_empty)") {
		t.Errorf("delete demo: código %d, stderr %q; quero 1 e 409 project_not_empty", code, stderr)
	}
	_, stdout, _ = runEnvmem(t, "run", "--servidor", url, "--ca", ca, "--projeto", "demo", "--", "sh", "-c", `echo "$DB_PASSWORD"`)
	if stdout != value+"\n" {
		t.Errorf("depois do delete recusado, stdout = %q, quero o segredo intacto", stdout)
	}

	runEnvmem(t, projects("create", "vazio")...)
	if _, stdout, _ := runEnvmem(t, projects("delete", "vazio")...); stdout != "projeto vazio removido\n" {
		t.Errorf("delete vazio: stdout = %q", stdout)
	}
	if _, stdout, _ := runEnvmem(t, projects("list")...); stdout != "demo\n" {
		t.Errorf("list depois dos deletes: stdout = %q, quero %q", stdout, "demo\n")
	}

	_, _, stderr, code = execEnvmem(t, projects("delete", "vazio")...)
	if code != 1 || !strings.Contains(stderr, "404 (project_not_found)") {
		t.Errorf("delete repetido: código %d, stderr %q; quero 1 e 404 project_not_found", code, stderr)
	}
}

// runEnvmem roda o envmem (o próprio binário de teste) num processo filho e
// falha o teste se ele sair com erro.
func runEnvmem(t *testing.T, args ...string) (pid int, stdout, stderr string) {
	t.Helper()
	pid, stdout, stderr, code := execEnvmem(t, args...)
	if code != 0 {
		t.Fatalf("envmem %v: saiu com %d\nstderr: %s", args, code, stderr)
	}
	return pid, stdout, stderr
}

// execEnvmem roda o envmem num processo filho e devolve também o código de
// saída, para os casos em que o erro é o resultado esperado.
func execEnvmem(t *testing.T, args ...string) (pid int, stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestEndToEnd$")
	cmd.Env = append(os.Environ(), e2eEnv+"="+strings.Join(args, "\x1f"))
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	// Sair com código diferente de zero é um resultado; não conseguir nem
	// iniciar o processo é falha do teste.
	var exitErr *exec.ExitError
	if err := cmd.Run(); err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("envmem %v: %v", args, err)
	}
	return cmd.Process.Pid, out.String(), errOut.String(), cmd.ProcessState.ExitCode()
}

func request(t *testing.T, hc *http.Client, method, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func wantStatus(t *testing.T, step string, want int, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s: status = %d, quero %d (%s)", step, resp.StatusCode, want, body)
	}
}

func assertNoPlaintextInDB(t *testing.T, dbURL, value string) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	var ciphertext, wrappedDEK []byte
	err = conn.QueryRow(context.Background(),
		`SELECT s.ciphertext, s.wrapped_dek
		 FROM secrets s JOIN projects p ON p.id = s.project_id
		 WHERE p.name = $1 AND s.key = $2`,
		"demo", "DB_PASSWORD").Scan(&ciphertext, &wrappedDEK)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(value)) || bytes.Contains(wrappedDEK, []byte(value)) {
		t.Fatal("o valor aparece em claro no banco")
	}
}

// tempSchemaURL cria um schema temporário e devolve a URL do banco, como
// dono, apontando para ele (search_path). O schema é apagado no fim do teste.
func tempSchemaURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_MIGRATE_URL")
	if url == "" {
		t.Skip("DATABASE_MIGRATE_URL não definida (URL do usuário dono do banco)")
	}
	ctx := context.Background()
	schema := "test_" + strings.ToLower(rand.Text()[:10])
	ident := pgx.Identifier{schema}.Sanitize()

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	// As migrações dão privilégios ao envmem_app, então ele precisa existir
	// (em desenvolvimento, quem o cria é o scripts/db-init). A exceção cobre
	// outro pacote de teste criando ao mesmo tempo.
	ensureAppRole := `DO $$ BEGIN CREATE ROLE envmem_app NOLOGIN;
		EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$`
	if _, err := conn.Exec(ctx, ensureAppRole); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+ident+"; GRANT USAGE ON SCHEMA "+ident+" TO envmem_app"); err != nil {
		t.Fatal(err)
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

	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	return url + sep + "search_path=" + schema
}
