package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heschaefer/envmem/internal/client"
)

// newServer sobe um servidor simulado com as mesmas rotas e respostas da
// API. A integração com o servidor real (banco e cofre) é testada no teste
// de ponta a ponta.
func newServer(t *testing.T) *client.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"ok","sealed":false}`)
	})
	mux.HandleFunc("GET /v1/projects/{project}/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("project") != "demo" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"project_not_found","message":"projeto não encontrado"}`)
			return
		}
		io.WriteString(w, `{"project":"demo","secrets":[{"key":"DB_PASSWORD","value":"x"}]}`)
	})
	mux.HandleFunc("GET /v1/projects", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"projects":[{"id":"1","name":"app-homo"},{"id":"2","name":"demo"}]}`)
	})
	mux.HandleFunc("POST /v1/projects", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Name string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.Name == "demo" {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"error":"project_exists","message":"já existe um projeto com esse nome"}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"id":"3","name":%q}`, in.Name)
	})
	mux.HandleFunc("DELETE /v1/projects/{project}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("project") != "demo" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"project_not_found","message":"projeto não encontrado"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
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
	if h.Status != "ok" || h.Sealed {
		t.Errorf("health = %+v, quero ok e aberto", h)
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

func TestProjects(t *testing.T) {
	c := newServer(t)
	ctx := context.Background()

	list, err := c.Projects(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "app-homo" {
		t.Fatalf("Projects = %+v, %v", list, err)
	}

	p, err := c.CreateProject(ctx, "app-prod")
	if err != nil || p.Name != "app-prod" || p.ID == "" {
		t.Fatalf("CreateProject = %+v, %v", p, err)
	}
	var apiErr *client.APIError
	if _, err := c.CreateProject(ctx, "demo"); !errors.As(err, &apiErr) || apiErr.Code != "project_exists" {
		t.Fatalf("CreateProject repetido: %v, quero project_exists", err)
	}

	if err := c.DeleteProject(ctx, "demo"); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	if err := c.DeleteProject(ctx, "nao-existe"); !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("DeleteProject inexistente: %v, quero 404", err)
	}
	if err := c.DeleteProject(ctx, ""); err == nil {
		t.Fatal("esperava erro para projeto vazio")
	}
}
