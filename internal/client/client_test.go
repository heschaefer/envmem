package client_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heschaefer/envmem/internal/api"
	"github.com/heschaefer/envmem/internal/client"
)

// newServer sobe o roteador real do servidor num endereço local de teste.
func newServer(t *testing.T) *client.Client {
	t.Helper()
	srv := httptest.NewServer(api.NewRouter(slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestHealth(t *testing.T) {
	c := newServer(t)
	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Status != "ok" {
		t.Errorf("Status = %q, quero \"ok\"", h.Status)
	}
}

func TestSecrets(t *testing.T) {
	c := newServer(t)
	secrets, err := c.Secrets(context.Background(), "demo")
	if err != nil {
		t.Fatalf("Secrets: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Key != "DB_PASSWORD" || secrets[0].Value == "" {
		t.Errorf("segredos inesperados: %d itens", len(secrets))
	}
}

func TestSecretsErrors(t *testing.T) {
	tests := []struct {
		name, project, code string
	}{
		{"projeto inexistente", "nao-existe", "project_not_found"},
		// Com o PathEscape, a barra não vira um novo segmento da rota: o
		// servidor recebe "a/b" como nome de projeto e responde 404 do projeto.
		{"barra no nome", "a/b", "project_not_found"},
		{"tentativa de subir de diretório", "../health", "project_not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newServer(t)
			_, err := c.Secrets(context.Background(), tt.project)

			var apiErr *client.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("erro = %v, quero *APIError", err)
			}
			if apiErr.Status != http.StatusNotFound || apiErr.Code != tt.code {
				t.Errorf("erro = %d %q, quero 404 %q", apiErr.Status, apiErr.Code, tt.code)
			}
		})
	}
}

func TestSecretsEmptyProject(t *testing.T) {
	c := newServer(t)
	if _, err := c.Secrets(context.Background(), ""); err == nil {
		t.Fatal("esperava erro para projeto vazio")
	}
}

// Um erro fora do formato da API (HTML de um proxy, por exemplo) ainda vira
// *APIError, só com o status.
func TestNonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	c, _ := client.New(srv.URL)

	_, err := c.Health(context.Background())
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadGateway || apiErr.Code != "" {
		t.Fatalf("erro = %v, quero *APIError 502 sem código", err)
	}
}

// Se o corpo de uma resposta 200 vier corrompido, o erro não pode repetir
// trechos dele, porque o corpo pode conter segredos.
func TestInvalidBodyDoesNotLeak(t *testing.T) {
	const leaked = "VALOR-SECRETO"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"secrets": [` + leaked))
	}))
	t.Cleanup(srv.Close)
	c, _ := client.New(srv.URL)

	_, err := c.Secrets(context.Background(), "demo")
	if err == nil {
		t.Fatal("esperava erro para corpo inválido")
	}
	if strings.Contains(err.Error(), leaked) {
		t.Fatalf("mensagem de erro vaza o corpo: %v", err)
	}
}

func TestNewRejectsInvalidURL(t *testing.T) {
	for _, u := range []string{"", "localhost:8080", "ftp://x", "http://"} {
		if _, err := client.New(u); err == nil {
			t.Errorf("New(%q): esperava erro", u)
		}
	}
}
