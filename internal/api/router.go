// Package api implementa as rotas HTTP do envmem-server.
package api

import (
	"log/slog"
	"net/http"
	"time"
)

// NewRouter monta as rotas da API, com log de cada requisição.
func NewRouter(logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", handleHealth)
	mux.HandleFunc("GET /v1/projects/{project}/secrets", handleListSecrets)

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
