// Package api implementa as rotas HTTP do envmem-server.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/heschaefer/envmem/internal/auth"
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
	UserByEmail(ctx context.Context, email string) (store.User, error)
	CreateSession(ctx context.Context, tokenHash []byte, userID string, expiresAt time.Time) error
	UserBySession(ctx context.Context, tokenHash []byte) (store.User, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error
	ChangePassword(ctx context.Context, userID, passwordHash string, keepTokenHash []byte) error
	LatestSecrets(ctx context.Context, projectID string) ([]store.SecretRow, error)
	InsertSecretVersion(ctx context.Context, row store.SecretRow) (int, error)
}

// maxConcurrentHashes limita quantas conferências de senha (argon2id, 19
// MiB cada) rodam ao mesmo tempo.
const maxConcurrentHashes = 4

// server reúne as dependências dos handlers.
type server struct {
	logger    *slog.Logger
	store     Store
	vault     *vault.Vault
	limiter   *auth.Limiter
	hashSlots chan struct{}
	now       func() time.Time
}

// NewRouter monta as rotas da API, com log de cada requisição.
func NewRouter(logger *slog.Logger, st Store, v *vault.Vault) http.Handler {
	return newRouter(logger, st, v, time.Now)
}

// newRouter é o NewRouter com o relógio como parâmetro, para os testes.
func newRouter(logger *slog.Logger, st Store, v *vault.Vault, now func() time.Time) http.Handler {
	s := &server{
		logger:    logger,
		store:     st,
		vault:     v,
		limiter:   auth.NewLimiter(auth.LoginMaxFailures, auth.LoginBlock, now),
		hashSlots: make(chan struct{}, maxConcurrentHashes),
		now:       now,
	}

	mux := http.NewServeMux()

	// Rotas públicas: a lista é explícita e curta (decisão 5). O unseal não
	// exige sessão porque a própria chave-mestra é a credencial (decisão 2),
	// e o login é justamente onde a sessão nasce.
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/unseal", s.handleUnseal)
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)

	// Todas as outras exigem sessão. Registrá-las só por esta função faz a
	// falha ser fechada: uma rota nova sem autenticação teria de ser posta,
	// de propósito, na lista acima.
	private := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, s.requireAuth(h))
	}
	private("POST /v1/auth/logout", s.handleLogout)
	private("GET /v1/auth/me", s.handleMe)
	private("POST /v1/auth/password", s.handleChangePassword)
	private("GET /v1/projects", s.handleListProjects)
	private("POST /v1/projects", s.handleCreateProject)
	private("DELETE /v1/projects/{project}", s.handleDeleteProject)
	private("GET /v1/projects/{project}/secrets", s.handleListSecrets)
	private("PUT /v1/projects/{project}/secrets/{key}", s.handlePutSecret)

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
