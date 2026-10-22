package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	_, c := newTLSServer(t, mux, tls.VersionTLS13)
	return c
}

// newTLSServer sobe h num servidor HTTPS de teste que aceita até maxVersion
// de TLS, e devolve um cliente que confia no certificado dele.
func newTLSServer(t *testing.T, h http.Handler, maxVersion uint16) (*httptest.Server, *client.Client) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{MaxVersion: maxVersion}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	c, err := client.New(srv.URL, roots)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, c
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
	_, c := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
	}), tls.VersionTLS13)

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
	_, c := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"secrets": [` + leaked))
	}), tls.VersionTLS13)

	_, err := c.Secrets(context.Background(), "demo")
	if err == nil {
		t.Fatal("esperava erro para corpo inválido")
	}
	if strings.Contains(err.Error(), leaked) {
		t.Fatalf("mensagem de erro vaza o corpo: %v", err)
	}
}

// Sem TLS, nem tenta: http:// é recusado antes de qualquer conexão.
func TestNewRejectsInvalidURL(t *testing.T) {
	for _, u := range []string{"", "localhost:8080", "ftp://x", "https://", "http://localhost:8080"} {
		if _, err := client.New(u, nil); err == nil {
			t.Errorf("New(%q): esperava erro", u)
		}
	}
}

// Um servidor cujo certificado não foi assinado pela CA informada é
// recusado no handshake, antes de qualquer requisição chegar a ele.
func TestRejectsUnknownCA(t *testing.T) {
	called := false
	srv, _ := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}), tls.VersionTLS13)

	// Outra CA no lugar da certa. Não serve o certificado de um segundo
	// httptest.Server: todos usam o mesmo certificado fixo do Go.
	roots := x509.NewCertPool()
	roots.AddCert(newCA(t))

	for name, pool := range map[string]*x509.CertPool{"outra CA": roots, "CAs do sistema": nil} {
		c, _ := client.New(srv.URL, pool)
		_, err := c.Health(context.Background())
		if err == nil || !strings.Contains(err.Error(), "CA confiável") {
			t.Errorf("%s: erro = %v, quero recusa do certificado", name, err)
		}
	}
	if called {
		t.Fatal("a requisição chegou ao servidor com certificado não confiável")
	}
}

// newCA gera uma CA autoassinada nova, só para confiar nela no lugar da
// certa.
func newCA(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "outra CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// O cliente recusa um servidor que só fala TLS 1.2.
func TestRejectsTLS12Server(t *testing.T) {
	_, c := newTLSServer(t, http.NotFoundHandler(), tls.VersionTLS12)
	if _, err := c.Health(context.Background()); err == nil {
		t.Fatal("esperava erro: servidor só com TLS 1.2")
	}
}

func TestLoadCA(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	good := filepath.Join(dir, "ca.crt")
	os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)
	if _, err := client.LoadCA(good); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	bad := filepath.Join(dir, "lixo.crt")
	os.WriteFile(bad, []byte("não é PEM"), 0o644)
	for _, path := range []string{bad, filepath.Join(dir, "nao-existe.crt")} {
		if _, err := client.LoadCA(path); err == nil {
			t.Errorf("LoadCA(%s): esperava erro", path)
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

// O token vai no cabeçalho Authorization, e só depois de SetToken.
func TestTokenHeader(t *testing.T) {
	var got []string
	_, c := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		if strings.Contains(r.URL.String(), "tok") {
			t.Error("o token apareceu na URL")
		}
		io.WriteString(w, `{"status":"ok","sealed":false}`)
	}), tls.VersionTLS13)

	c.Health(context.Background())
	c.SetToken("tok123")
	c.Health(context.Background())
	if len(got) != 2 || got[0] != "" || got[1] != "Bearer tok123" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestLogin(t *testing.T) {
	_, c := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Email, Password string }
		json.NewDecoder(r.Body).Decode(&in)
		if r.URL.Path != "/v1/auth/login" || in.Password != "senha certa longa" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"invalid_credentials","message":"e-mail ou senha incorretos"}`)
			return
		}
		io.WriteString(w, `{"token":"t","expires_at":"2026-10-22T20:00:00Z","must_change_password":true}`)
	}), tls.VersionTLS13)

	res, err := c.Login(context.Background(), "a@b.com", "senha certa longa")
	if err != nil || res.Token != "t" || !res.MustChangePassword {
		t.Fatalf("Login = %+v, %v", res, err)
	}
	var apiErr *client.APIError
	if _, err := c.Login(context.Background(), "a@b.com", "errada"); !errors.As(err, &apiErr) || apiErr.Code != "invalid_credentials" {
		t.Fatalf("senha errada: %v", err)
	}
}
