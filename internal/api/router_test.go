package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestRouter(t *testing.T) (http.Handler, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	return NewRouter(slog.New(slog.NewJSONHandler(&logs, nil))), &logs
}

func do(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHealth(t *testing.T) {
	h, _ := newTestRouter(t)
	rec := do(t, h, http.MethodGet, "/v1/health")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, quero 200", rec.Code)
	}
	var body healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decodificar: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, quero \"ok\"", body.Status)
	}
}

func TestListSecretsDemo(t *testing.T) {
	h, _ := newTestRouter(t)
	rec := do(t, h, http.MethodGet, "/v1/projects/demo/secrets")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, quero 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, quero no-store", got)
	}
	var body listSecretsResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decodificar: %v", err)
	}
	if body.Project != "demo" || len(body.Secrets) != 1 || body.Secrets[0].Key != "DB_PASSWORD" {
		t.Errorf("resposta inesperada: %+v", body)
	}
}

func TestErrorsAreJSON(t *testing.T) {
	tests := []struct {
		name, method, path, code string
	}{
		{"projeto inexistente", http.MethodGet, "/v1/projects/nao-existe/secrets", "project_not_found"},
		{"rota inexistente", http.MethodGet, "/v1/nada", "not_found"},
		{"método não suportado", http.MethodPost, "/v1/health", "not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := newTestRouter(t)
			rec := do(t, h, tt.method, tt.path)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, quero 404", rec.Code)
			}
			var body errorBody
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("erro não é JSON: %v", err)
			}
			if body.Error != tt.code {
				t.Errorf("error = %q, quero %q", body.Error, tt.code)
			}
		})
	}
}

// O log nunca pode conter o valor de um segredo.
func TestLogsDoNotContainSecretValues(t *testing.T) {
	h, logs := newTestRouter(t)
	do(t, h, http.MethodGet, "/v1/projects/demo/secrets")

	if logs.Len() == 0 {
		t.Fatal("esperava uma linha de log da requisição")
	}
	for _, s := range fixedSecrets["demo"] {
		if strings.Contains(logs.String(), s.Value) {
			t.Fatalf("log contém o valor do segredo %s", s.Key)
		}
	}
}
