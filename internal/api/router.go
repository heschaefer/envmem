// Package api implementa as rotas HTTP do envmem-server.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
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
	MemberRole(ctx context.Context, projectID, userID string) (string, error)
	ProjectsForMember(ctx context.Context, userID string) ([]store.ProjectMembership, error)
	ListMembers(ctx context.Context, projectID string) ([]store.Member, error)
	SetMember(ctx context.Context, projectID, userID, role string) error
	RemoveMember(ctx context.Context, projectID, userID string) error
	ListUsers(ctx context.Context) ([]store.User, error)
	CreateUser(ctx context.Context, email, globalRole, passwordHash string, tempExpiresAt time.Time) (store.User, error)
	DeleteUser(ctx context.Context, id string) error
	ResetPassword(ctx context.Context, id, passwordHash string, tempExpiresAt time.Time) error
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

	// Todas as outras exigem sessão e uma permissão (decisão 5), e só podem
	// ser registradas por esta função: não existe rota autenticada sem
	// permissão declarada. A falha é fechada: uma rota sem sessão teria de
	// ser posta, de propósito, na lista acima.
	route := func(pattern string, p auth.Permission, h http.HandlerFunc) {
		// Uma permissão de projeto numa rota sem {project} não teria como
		// ser conferida: erro de programação, que impede o servidor de subir.
		if p.Project && !strings.Contains(pattern, "{project}") {
			panic("api: permissão de projeto " + p.Name + " na rota sem {project}: " + pattern)
		}
		mux.HandleFunc(pattern, s.requireAuth(s.authorize(p, h)))
	}
	route("POST /v1/seal", auth.PermSeal, s.handleSeal)
	route("POST /v1/auth/logout", auth.PermSession, s.handleLogout)
	route("GET /v1/auth/me", auth.PermSession, s.handleMe)
	route("POST /v1/auth/password", auth.PermSession, s.handleChangePassword)
	route("GET /v1/projects", auth.PermSession, s.handleListProjects)
	route("POST /v1/projects", auth.PermManageProjects, s.handleCreateProject)
	route("DELETE /v1/projects/{project}", auth.PermManageProjects, s.handleDeleteProject)
	route("GET /v1/projects/{project}/members", auth.PermManageMembers, s.handleListMembers)
	route("POST /v1/projects/{project}/members", auth.PermManageMembers, s.handleSetMember)
	route("DELETE /v1/projects/{project}/members/{user}", auth.PermManageMembers, s.handleRemoveMember)
	route("GET /v1/users", auth.PermManageUsers, s.handleListUsers)
	route("POST /v1/users", auth.PermManageUsers, s.handleCreateUser)
	route("DELETE /v1/users/{user}", auth.PermManageUsers, s.handleDeleteUser)
	route("POST /v1/users/{user}/password/reset", auth.PermManageUsers, s.handleResetPassword)
	route("GET /v1/projects/{project}/secrets", auth.PermUseSecrets, s.handleListSecrets)
	route("PUT /v1/projects/{project}/secrets/{key}", auth.PermWriteSecrets, s.handlePutSecret)

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
