//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base32"
	"encoding/json"
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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/heschaefer/envmem/internal/api"
	"github.com/heschaefer/envmem/internal/auth"
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

	// Primeiro superadmin, como o "envmem-server create-superadmin" faria.
	const email, password = "admin@empresa.com", "senha do superadmin de teste"
	if _, err := st.CreateFirstSuperadmin(ctx, email, auth.HashPassword([]byte(password))); err != nil {
		t.Fatal(err)
	}
	// O ~/.config dos processos do CLI fica numa pasta temporária. A
	// variável ENVMEM_SEGREDO_TESTE serve para conferir que o run não passa
	// variáveis ENVMEM_* para a aplicação.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ENVMEM_SEGREDO_TESTE", "nao-pode-chegar-na-aplicacao")

	// startServer simula uma subida do envmem-server: cofre novo (selado),
	// mesmo banco, só TLS 1.3. hc é um cliente HTTP que confia no
	// certificado do servidor e envia o token de sessão, para os passos
	// feitos "com curl".
	var hc *http.Client
	var token string
	ca := filepath.Join(t.TempDir(), "ca.crt")
	startServer := func() string {
		srv := httptest.NewUnstartedServer(api.NewRouter(slog.New(slog.DiscardHandler), api.FromStore(st), vault.New()))
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		hc = &http.Client{Transport: bearerTransport{base: srv.Client().Transport, token: &token}}
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

	// 0. Sem sessão, nada além das rotas públicas. O superadmin precisa de
	// MFA (decisão 36), e o segredo do TOTP é cifrado pelo cofre: com o
	// servidor selado, nem a senha certa abre sessão.
	url := startServer()
	wantStatus(t, "GET sem sessão", http.StatusUnauthorized,
		request(t, hc, http.MethodGet, url+"/v1/projects", ""))
	login := func(stdin string) (stdout, stderr string, code int) {
		_, stdout, stderr, code = execEnvmemIn(t, stdin, "login", "--servidor", url, "--ca", ca, "--senha-stdin", email)
		return stdout, stderr, code
	}
	if _, stderr, code := login("senha errada mas longa\n"); code != 1 || !strings.Contains(stderr, "invalid_credentials") {
		t.Errorf("login com senha errada: código %d, stderr %q", code, stderr)
	}
	if _, stderr, code := login(password + "\n"); code != 1 || !strings.Contains(stderr, "sealed") {
		t.Errorf("login selado: código %d, stderr %q; quero recusa por cofre selado", code, stderr)
	}

	// 1. Unseal com a chave gerada.
	wantStatus(t, "unseal", http.StatusOK,
		request(t, hc, http.MethodPost, url+"/v1/unseal", `{"key":"`+key+`"}`))

	// 2. Primeiro login do superadmin: o MFA ainda não foi cadastrado, e o
	// cadastro (QR code e chave) precisa de um terminal; pelo pipe, o CLI
	// recusa. O teste cadastra pela API, como o CLI faria no terminal.
	if _, stderr, code := login(password + "\n"); code != 1 || !strings.Contains(stderr, "num terminal") {
		t.Errorf("cadastro do MFA pelo pipe: código %d, stderr %q", code, stderr)
	}
	secret := enrollMFA(t, hc, url, email, password)
	// Com o MFA cadastrado, o login pelo pipe lê a senha e o código, uma
	// linha cada. Código errado: recusado, sem nova tentativa pelo pipe.
	if _, stderr, code := login(password + "\n" + wrongTOTP(secret) + "\n"); code != 1 || !strings.Contains(stderr, "invalid_mfa_code") {
		t.Errorf("login com código errado: código %d, stderr %q", code, stderr)
	}
	// O código do passo atual já foi usado no cadastro (cada um vale uma
	// vez); o do passo seguinte é aceito pela tolerância de um passo.
	runEnvmemIn(t, password+"\n"+auth.TOTPCode(secret, time.Now().Add(30*time.Second))+"\n",
		"login", "--servidor", url, "--ca", ca, "--senha-stdin", email)
	if token, err = loadToken(); err != nil {
		t.Fatalf("o login deveria ter gravado o token: %v", err)
	}
	if cfg, err := loadConfig(); err != nil || cfg != (cliConfig{Server: url, CA: ca}) {
		t.Fatalf("config.json = %+v, %v; quero servidor %s e CA %s", cfg, err, url, ca)
	}

	// Projeto demo criado pelo CLI.
	if _, stdout, _ := runEnvmem(t, "projects", "create", "demo"); stdout != "projeto demo criado\n" {
		t.Errorf("projects create: stdout = %q", stdout)
	}

	// 3. Lista os projetos pelo CLI e grava o segredo DB_PASSWORD no demo,
	// também pelo CLI.
	if _, stdout, _ := runEnvmem(t, "projects", "list"); stdout != "demo  superadmin\n" {
		t.Errorf("projects list: stdout = %q, quero %q", stdout, "demo  superadmin\n")
	}
	// Pelo pipe, criar uma variável nova exige --criar: um nome digitado
	// errado num script não cria variável em silêncio.
	if _, _, stderr, code := execEnvmemIn(t, value+"\n", "secrets", "set", "--projeto", "demo", "--valor-stdin", "DB_PASSWORD"); code != 1 || !strings.Contains(stderr, "--criar") {
		t.Errorf("set sem --criar: código %d, stderr %q", code, stderr)
	}
	// Versão 1 com um valor provisório, versão 2 com o valor certo.
	runEnvmemIn(t, "provisorio\n", "secrets", "set", "--projeto", "demo", "--valor-stdin", "--criar", "DB_PASSWORD")
	if _, stdout, _ := runEnvmemIn(t, value+"\n", "secrets", "set", "--projeto", "demo", "--valor-stdin", "DB_PASSWORD"); stdout != "DB_PASSWORD gravada no projeto demo (versão 2)\n" {
		t.Errorf("set: stdout = %q", stdout)
	}
	if _, stdout, _ := runEnvmem(t, "secrets", "get", "--projeto", "demo", "--versao", "1", "DB_PASSWORD"); stdout != "provisorio\n" {
		t.Errorf("get --versao 1: stdout = %q", stdout)
	}
	if _, stdout, _ := runEnvmem(t, "secrets", "get", "--projeto", "demo", "DB_PASSWORD"); stdout != value+"\n" {
		t.Errorf("get: stdout = %q", stdout)
	}
	// O list mostra nomes e versões, nunca valores; sem --projeto, percorre
	// todos os projetos do usuário.
	var pid int
	var stdout, stderr string
	_, stdout, _ = runEnvmem(t, "secrets", "list")
	if !strings.HasPrefix(stdout, "demo (superadmin)\n  DB_PASSWORD  v2  ") || strings.Contains(stdout, value) {
		t.Errorf("secrets list: stdout = %q", stdout)
	}
	// Lixeira: o rm tira a variável do run e da listagem; o restore a traz
	// de volta.
	runEnvmem(t, "secrets", "rm", "--projeto", "demo", "DB_PASSWORD")
	if _, stdout, _ := runEnvmem(t, "secrets", "list", "--projeto", "demo"); stdout != "" {
		t.Errorf("list depois do rm: stdout = %q, quero vazio", stdout)
	}
	if _, stdout, _ := runEnvmem(t, "secrets", "trash", "--projeto", "demo"); !strings.HasPrefix(stdout, "DB_PASSWORD  v2  removida em ") {
		t.Errorf("trash: stdout = %q", stdout)
	}
	runEnvmem(t, "secrets", "restore", "--projeto", "demo", "DB_PASSWORD")

	// 4. No banco, o valor está ilegível.
	assertNoPlaintextInDB(t, dbURL, value)

	// 5. envmem run: o comando recebe a senha, no mesmo PID que o envmem
	// imprimiu antes do exec, e não recebe as variáveis ENVMEM_*.
	pid, stdout, stderr = runEnvmem(t, "run", "--verbose", "--projeto", "demo",
		"--", "sh", "-c", `echo "$$ $DB_PASSWORD [$ENVMEM_SEGREDO_TESTE]"`)
	if want := fmt.Sprintf("envmem: pid %d,", pid); !strings.HasPrefix(stderr, want) {
		t.Errorf("stderr = %q, quero começar com %q", stderr, want)
	}
	if want := fmt.Sprintf("%d %s []\n", pid, value); stdout != want {
		t.Errorf("stdout = %q, quero %q", stdout, want)
	}

	// 6. Reinício: volta selado; só a mesma chave abre, e o segredo continua lá.
	// O servidor de teste sobe noutro endereço, diferente do config.json:
	// daqui em diante, --servidor sobrescreve o arquivo.
	url = startServer()
	wantStatus(t, "GET depois do reinício", http.StatusServiceUnavailable,
		request(t, hc, http.MethodGet, url+"/v1/projects/demo/secrets", ""))
	wantStatus(t, "unseal com outra chave", http.StatusUnauthorized,
		request(t, hc, http.MethodPost, url+"/v1/unseal", `{"key":"`+vault.EncodeKey(vault.GenerateKey())+`"}`))
	wantStatus(t, "unseal com a chave certa", http.StatusOK,
		request(t, hc, http.MethodPost, url+"/v1/unseal", `{"key":"`+key+`"}`))
	_, stdout, _ = runEnvmem(t, "run", "--servidor", url, "--projeto", "demo", "--", "sh", "-c", `echo "$DB_PASSWORD"`)
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
	if _, stdout, _ := runEnvmem(t, projects("list")...); stdout != "demo  superadmin\n" {
		t.Errorf("list depois dos deletes: stdout = %q, quero %q", stdout, "demo  superadmin\n")
	}

	_, _, stderr, code = execEnvmem(t, projects("delete", "vazio")...)
	if code != 1 || !strings.Contains(stderr, "404 (project_not_found)") {
		t.Errorf("delete repetido: código %d, stderr %q; quero 1 e 404 project_not_found", code, stderr)
	}

	// 7b. Usuários e membros: o superadmin cria um usuário pelo CLI (senha
	// temporária pelo stdin), que entra no demo como desenvolvedor, vira
	// gestor e sai. Os comandos recebem o e-mail; o CLI acha o id na lista.
	const devEmail = "dev@empresa.com"
	users := func(action string, args ...string) []string {
		return append([]string{"users", action, "--servidor", url}, args...)
	}
	if _, stdout, _ := runEnvmemIn(t, "senha temporaria do dev\n", users("create", "--senha-stdin", devEmail)...); !strings.HasPrefix(stdout, "usuário "+devEmail+" criado") {
		t.Errorf("users create: stdout = %q", stdout)
	}
	if _, stdout, _ := runEnvmem(t, users("list")...); !regexp.MustCompile(`(?m)^dev@empresa\.com +usuário +senha temporária$`).MatchString(stdout) ||
		!regexp.MustCompile(`(?m)^admin@empresa\.com +superadmin$`).MatchString(stdout) {
		t.Errorf("users list: stdout = %q", stdout)
	}
	runEnvmemIn(t, "outra senha temporaria\n", users("reset-password", "--senha-stdin", devEmail)...)
	// O servidor não deixa o superadmin remover a si mesmo.
	if _, _, stderr, code := execEnvmem(t, users("rm", "--sim", email)...); code != 1 || !strings.Contains(stderr, "cannot_remove_self") {
		t.Errorf("rm de si mesmo: código %d, stderr %q", code, stderr)
	}
	members := func(action string, args ...string) []string {
		return append([]string{"members", action, "--servidor", url, "--projeto", "demo"}, args...)
	}
	if _, stdout, _ := runEnvmem(t, members("add", devEmail)...); stdout != devEmail+" é desenvolvedor no projeto demo\n" {
		t.Errorf("members add: stdout = %q", stdout)
	}
	runEnvmem(t, members("add", "--papel", "gestor", "DEV@empresa.com")...)
	if _, stdout, _ := runEnvmem(t, members("list")...); stdout != devEmail+"  gestor\n" {
		t.Errorf("members list: stdout = %q", stdout)
	}
	runEnvmem(t, members("rm", devEmail)...)
	if _, _, stderr, code := execEnvmem(t, members("rm", devEmail)...); code != 1 || !strings.Contains(stderr, "não é membro") {
		t.Errorf("rm repetido: código %d, stderr %q", code, stderr)
	}
	// Remover usuário não tem volta: sem terminal para confirmar, exige --sim.
	if _, _, stderr, code := execEnvmem(t, users("rm", devEmail)...); code != 1 || !strings.Contains(stderr, "--sim") {
		t.Errorf("users rm sem --sim: código %d, stderr %q", code, stderr)
	}
	runEnvmem(t, users("rm", "--sim", devEmail)...)
	if _, stdout, _ := runEnvmem(t, users("list")...); strings.Contains(stdout, devEmail) {
		t.Errorf("users list depois do rm: stdout = %q", stdout)
	}

	// 8. Auditoria: cada run deixou uma linha por segredo entregue, com a
	// versão e o e-mail de quem rodou; nenhum valor aparece.
	resp := request(t, hc, http.MethodGet, url+"/v1/audit?project=demo&limit=1000", "")
	wantStatus(t, "GET /audit", http.StatusOK, resp)
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), value) {
		t.Fatal("a auditoria contém o valor do segredo")
	}
	for _, want := range []string{`"action":"secret.run"`, `"secret_key":"DB_PASSWORD"`, `"secret_version":1`, `"user_email":"` + email + `"`, `"action":"secret.write"`, `"action":"member.set"`, `"action":"member.remove"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("a auditoria deveria conter %s", want)
		}
	}

	// 9. Logout: revoga a sessão no servidor (o token antigo deixa de valer
	// na hora) e apaga o arquivo; sem sessão, o CLI pede login.
	runEnvmem(t, "logout", "--servidor", url, "--ca", ca)
	wantStatus(t, "token depois do logout", http.StatusUnauthorized,
		request(t, hc, http.MethodGet, url+"/v1/auth/me", ""))
	if _, err := loadToken(); !errors.Is(err, errNoSession) {
		t.Errorf("o arquivo do token deveria ter sido apagado: %v", err)
	}
	if _, _, stderr, code := execEnvmem(t, projects("list")...); code == 0 || !strings.Contains(stderr, "envmem login") {
		t.Errorf("sem sessão: código %d, stderr %q; quero erro pedindo login", code, stderr)
	}
}

// bearerTransport acrescenta o token de sessão (se houver) a cada
// requisição, como o CLI faz.
type bearerTransport struct {
	base  http.RoundTripper
	token *string
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if *b.token != "" {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+*b.token)
	}
	return b.base.RoundTrip(r)
}

// runEnvmem roda o envmem (o próprio binário de teste) num processo filho e
// falha o teste se ele sair com erro.
func runEnvmem(t *testing.T, args ...string) (pid int, stdout, stderr string) {
	t.Helper()
	return runEnvmemIn(t, "", args...)
}

// runEnvmemIn é o runEnvmem com stdin (por exemplo, a senha do login).
func runEnvmemIn(t *testing.T, stdin string, args ...string) (pid int, stdout, stderr string) {
	t.Helper()
	pid, stdout, stderr, code := execEnvmemIn(t, stdin, args...)
	if code != 0 {
		t.Fatalf("envmem %v: saiu com %d\nstderr: %s", args, code, stderr)
	}
	return pid, stdout, stderr
}

// execEnvmem roda o envmem num processo filho e devolve também o código de
// saída, para os casos em que o erro é o resultado esperado.
func execEnvmem(t *testing.T, args ...string) (pid int, stdout, stderr string, code int) {
	t.Helper()
	return execEnvmemIn(t, "", args...)
}

func execEnvmemIn(t *testing.T, stdin string, args ...string) (pid int, stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestEndToEnd$")
	cmd.Env = append(os.Environ(), e2eEnv+"="+strings.Join(args, "\x1f"))
	cmd.Stdin = strings.NewReader(stdin)
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

// enrollMFA cadastra o MFA de um usuário pela API, como o envmem login faz
// num terminal (login, setup e o primeiro código), e devolve o segredo.
func enrollMFA(t *testing.T, hc *http.Client, url, email, password string) []byte {
	t.Helper()
	resp := request(t, hc, http.MethodPost, url+"/v1/auth/login", `{"email":"`+email+`","password":"`+password+`"}`)
	wantStatus(t, "login para cadastrar o MFA", http.StatusOK, resp)
	var ch struct{ MFA, Challenge string }
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil || ch.MFA != "setup" {
		t.Fatalf("login: %+v, %v; quero desafio de cadastro", ch, err)
	}
	resp = request(t, hc, http.MethodPost, url+"/v1/auth/mfa/setup", `{"challenge":"`+ch.Challenge+`"}`)
	wantStatus(t, "setup do MFA", http.StatusOK, resp)
	var setup struct{ Secret string }
	if err := json.NewDecoder(resp.Body).Decode(&setup); err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "confirmar o MFA", http.StatusOK, request(t, hc, http.MethodPost, url+"/v1/auth/mfa",
		`{"challenge":"`+ch.Challenge+`","code":"`+auth.TOTPCode(secret, time.Now())+`"}`))
	return secret
}

// wrongTOTP devolve um código que não vale em nenhum dos passos aceitos
// agora (o atual e os vizinhos).
func wrongTOTP(secret []byte) string {
	valid := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second, 60 * time.Second} {
		valid[auth.TOTPCode(secret, time.Now().Add(d))] = true
	}
	for _, c := range []string{"000000", "111111", "222222"} {
		if !valid[c] {
			return c
		}
	}
	return "333333"
}
