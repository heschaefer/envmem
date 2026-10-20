// Package api implementa as rotas HTTP do envmem-server.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/heschaefer/envmem/internal/store"
	"github.com/heschaefer/envmem/internal/vault"
)

// Store é o que a API usa do banco. *store.Store a implementa; os testes da
// API usam uma versão em memória.
type Store interface {
	GetVaultMeta(ctx context.Context) (store.VaultMeta, error)
	InsertVaultMeta(ctx context.Context, m store.VaultMeta) (bool, error)
	CreateProject(ctx context.Context, name string) (store.Project, error)
	ProjectByName(ctx context.Context, name string) (store.Project, error)
	ListProjects(ctx context.Context) ([]store.Project, error)
	DeleteProject(ctx context.Context, name string) error
	LatestSecrets(ctx context.Context, projectID string) ([]store.SecretRow, error)
	InsertSecretVersion(ctx context.Context, row store.SecretRow) (int, error)
}

// server reúne as dependências dos handlers.
type server struct {
	logger *slog.Logger
	store  Store
	vault  *vault.Vault
}

// NewRouter monta as rotas da API, com log de cada requisição.
func NewRouter(logger *slog.Logger, st Store, v *vault.Vault) http.Handler {
	s := &server{logger: logger, store: st, vault: v}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/unseal", s.handleUnseal)
	mux.HandleFunc("GET /v1/projects", s.handleListProjects)
	mux.HandleFunc("POST /v1/projects", s.handleCreateProject)
	mux.HandleFunc("DELETE /v1/projects/{project}", s.handleDeleteProject)
	mux.HandleFunc("GET /v1/projects/{project}/secrets", s.handleListSecrets)
	mux.HandleFunc("PUT /v1/projects/{project}/secrets/{key}", s.handlePutSecret)

	// Qualquer outra rota (ou método) cai aqui, para que até o 404 siga o
	// formato de erro JSON da API em vez do texto puro do net/http.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "rota não encontrada")
	})

	return logRequests(logger, mux)
}

// logRequests registra método, caminho, status e duração de cada requisição.
// Nunca registra corpo, query string nem cabeçalhos: é onde segredos e tokens
// poderiam aparecer.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("requisição",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// statusRecorder guarda o status escrito pelo handler, para o log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
