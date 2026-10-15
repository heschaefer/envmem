//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	dbURL := tempSchemaURL(t)
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// startServer simula uma subida do envmem-server: cofre novo (selado),
	// mesmo banco.
	startServer := func() string {
		srv := httptest.NewServer(api.NewRouter(slog.New(slog.DiscardHandler), st, vault.New()))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	key := vault.EncodeKey(vault.GenerateKey())
	const value = "S3nh@-de-ponta-a-ponta"

	// 1. Sobe selado: GET de segredos devolve 503.
	url := startServer()
	wantStatus(t, "GET selado", http.StatusServiceUnavailable,
		request(t, http.MethodGet, url+"/v1/projects/demo/secrets", ""))

	// 2. Unseal com a chave gerada.
	wantStatus(t, "unseal", http.StatusOK,
		request(t, http.MethodPost, url+"/v1/unseal", `{"key":"`+key+`"}`))

	// 3. PUT do segredo DB_PASSWORD no projeto demo.
	wantStatus(t, "PUT", http.StatusCreated,
		request(t, http.MethodPut, url+"/v1/projects/demo/secrets/DB_PASSWORD", `{"value":"`+value+`"}`))

	// 4. No banco, o valor está ilegível.
	assertNoPlaintextInDB(t, dbURL, value)

	// 5. envmem run: o comando recebe a senha, no mesmo PID que o envmem
	// imprimiu antes do exec.
	pid, stdout, stderr := runEnvmem(t, "run", "--verbose", "--servidor", url, "--projeto", "demo",
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
		request(t, http.MethodGet, url+"/v1/projects/demo/secrets", ""))
	wantStatus(t, "unseal com outra chave", http.StatusUnauthorized,
		request(t, http.MethodPost, url+"/v1/unseal", `{"key":"`+vault.EncodeKey(vault.GenerateKey())+`"}`))
	wantStatus(t, "unseal com a chave certa", http.StatusOK,
		request(t, http.MethodPost, url+"/v1/unseal", `{"key":"`+key+`"}`))
	_, stdout, _ = runEnvmem(t, "run", "--servidor", url, "--projeto", "demo", "--", "sh", "-c", `echo "$DB_PASSWORD"`)
	if stdout != value+"\n" {
		t.Errorf("depois do reinício, stdout = %q, quero %q", stdout, value+"\n")
	}
}

// runEnvmem roda o envmem (o próprio binário de teste) num processo filho.
func runEnvmem(t *testing.T, args ...string) (pid int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestEndToEnd$")
	cmd.Env = append(os.Environ(), e2eEnv+"="+strings.Join(args, "\x1f"))
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("envmem %v: %v\nstderr: %s", args, err, errOut.String())
	}
	return cmd.Process.Pid, out.String(), errOut.String()
}

func request(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
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
		`SELECT ciphertext, wrapped_dek FROM secrets WHERE project = $1 AND key = $2`,
		"demo", "DB_PASSWORD").Scan(&ciphertext, &wrappedDEK)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(value)) || bytes.Contains(wrappedDEK, []byte(value)) {
		t.Fatal("o valor aparece em claro no banco")
	}
}

// tempSchemaURL cria um schema temporário e devolve a URL do banco apontando
// para ele (search_path). O schema é apagado no fim do teste.
func tempSchemaURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL não definida")
	}
	ctx := context.Background()
	schema := "test_" + strings.ToLower(rand.Text()[:10])
	ident := pgx.Identifier{schema}.Sanitize()

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
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
