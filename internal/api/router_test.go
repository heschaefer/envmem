package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/heschaefer/envmem/internal/vault"
)

// testEnv é um servidor de teste: roteador, cofre, store em memória, o log
// e um relógio falso, que o roteador e o store compartilham.
type testEnv struct {
	h     http.Handler
	vault *vault.Vault
	store *memStore
	logs  *bytes.Buffer
	clock *testClock
}

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time      { return c.t }
func (c *testClock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	clock := &testClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	e := &testEnv{vault: vault.New(), store: &memStore{now: clock.now}, logs: &bytes.Buffer{}, clock: clock}
	e.h = newRouter(slog.New(slog.NewJSONHandler(e.logs, nil)), e.store, e.vault, clock.now)
	return e
}

func (e *testEnv) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return e.doAs(t, "", method, path, body)
}

// doAs faz a requisição com o token no cabeçalho Authorization (se não for
// vazio).
func (e *testEnv) doAs(t *testing.T, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// unseal abre o cofre pela API com key (em base64) e devolve a resposta.
func (e *testEnv) unseal(t *testing.T, key string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodPost, "/v1/unseal", `{"key":"`+key+`"}`)
}

// createProject cria um projeto pela API e devolve o que ela respondeu.
func (e *testEnv) createProject(t *testing.T, name string) projectItem {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/v1/projects", `{"name":"`+name+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("criar projeto %q: %d %s", name, rec.Code, rec.Body.String())
	}
	return decode[projectItem](t, rec)
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("resposta não é JSON: %v", err)
	}
	return v
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, quero %d (corpo: %s)", rec.Code, status, rec.Body.String())
	}
	if body := decode[errorBody](t, rec); body.Error != code {
		t.Fatalf("error = %q, quero %q", body.Error, code)
	}
}

func TestHealthShowsSealed(t *testing.T) {
	e := newTestEnv(t)

	rec := e.do(t, http.MethodGet, "/v1/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, quero 200", rec.Code)
	}
	if h := decode[healthResponse](t, rec); h.Status != "ok" || !h.Sealed {
		t.Fatalf("health = %+v, quero ok e selado", h)
	}

	e.unseal(t, vault.EncodeKey(vault.GenerateKey()))
	if h := decode[healthResponse](t, e.do(t, http.MethodGet, "/v1/health", "")); h.Sealed {
		t.Fatal("health ainda selado depois do unseal")
	}
}

func TestUnsealFirstTimeThenRestart(t *testing.T) {
	e := newTestEnv(t)
	key := vault.EncodeKey(vault.GenerateKey())

	// Primeiro unseal: cria o valor de verificação.
	if rec := e.unseal(t, key); rec.Code != http.StatusOK {
		t.Fatalf("primeiro unseal: %d %s", rec.Code, rec.Body.String())
	}
	if e.store.meta == nil {
		t.Fatal("valor de verificação não foi gravado")
	}

	// "Reinício": cofre novo (selado), mesmo banco.
	restarted := &testEnv{vault: vault.New(), store: e.store, logs: &bytes.Buffer{}, clock: e.clock}
	restarted.h = NewRouter(slog.New(slog.DiscardHandler), restarted.store, restarted.vault)

	wantError(t, restarted.unseal(t, vault.EncodeKey(vault.GenerateKey())),
		http.StatusUnauthorized, "invalid_master_key")
	if !restarted.vault.Sealed() {
		t.Fatal("chave errada abriu o cofre")
	}

	if rec := restarted.unseal(t, key); rec.Code != http.StatusOK {
		t.Fatalf("unseal com a chave certa: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUnsealErrors(t *testing.T) {
	e := newTestEnv(t)
	key := vault.EncodeKey(vault.GenerateKey())

	wantError(t, e.do(t, http.MethodPost, "/v1/unseal", `não é json`), http.StatusBadRequest, "invalid_body")
	wantError(t, e.do(t, http.MethodPost, "/v1/unseal", `{"chave":"x"}`), http.StatusBadRequest, "invalid_body")
	wantError(t, e.unseal(t, "curta"), http.StatusBadRequest, "invalid_key")
	wantError(t, e.unseal(t, vault.EncodeKey(make([]byte, 16))), http.StatusBadRequest, "invalid_key")

	e.unseal(t, key)
	wantError(t, e.unseal(t, key), http.StatusConflict, "already_unsealed")
}

// Nem a chave-mestra nem o seu base64 podem aparecer no log, mesmo quando o
// unseal falha.
func TestLogsDoNotContainMasterKey(t *testing.T) {
	e := newTestEnv(t)
	right := vault.EncodeKey(vault.GenerateKey())
	wrong := vault.EncodeKey(vault.GenerateKey())

	e.unseal(t, right)
	e.vault.Seal()
	e.unseal(t, wrong)

	for _, k := range []string{right, wrong} {
		if strings.Contains(e.logs.String(), k) {
			t.Fatal("log contém a chave-mestra")
		}
	}
}

func TestErrorsAreJSON(t *testing.T) {
	tests := []struct {
		name, method, path, code string
	}{
		{"rota inexistente", http.MethodGet, "/v1/nada", "not_found"},
		{"método não suportado", http.MethodPost, "/v1/health", "not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEnv(t)
			wantError(t, e.do(t, tt.method, tt.path, ""), http.StatusNotFound, tt.code)
		})
	}
}
