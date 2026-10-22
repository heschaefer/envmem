package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/heschaefer/envmem/internal/store"
)

// pgStore adapta o *store.Store à interface Store: o InTx do store entrega
// um *store.Store, e os handlers trabalham com a interface.
type pgStore struct{ *store.Store }

// FromStore embrulha o store do PostgreSQL para o NewRouter.
func FromStore(st *store.Store) Store { return pgStore{st} }

func (p pgStore) InTx(ctx context.Context, fn func(tx Store) error) error {
	return p.Store.InTx(ctx, func(tx *store.Store) error { return fn(pgStore{tx}) })
}

// event monta um evento de auditoria com quem fez a requisição, o IP de
// origem e o projeto da rota, quando houver.
func (s *server) event(r *http.Request, action, result string) store.AuditEvent {
	e := store.AuditEvent{Action: action, Result: result, RemoteAddr: auditIP(r)}
	if u := sessionFrom(r.Context()).user; u.ID != "" {
		e.UserID, e.UserEmail = u.ID, u.Email
	}
	if p := projectFrom(r.Context()).project; p.ID != "" {
		e.ProjectID, e.ProjectName = p.ID, p.Name
	}
	return e
}

// auditIP é o IP de origem no formato que a coluna inet aceita (sem zona
// de IPv6), ou vazio se não for um IP.
func auditIP(r *http.Request) string {
	addr, err := netip.ParseAddr(clientIP(r))
	if err != nil {
		return ""
	}
	return addr.WithZone("").String()
}

// recordDenied registra uma negação. A negação vale de qualquer jeito, mesmo
// que o registro falhe; nesse caso, o erro vai para o log.
func (s *server) recordDenied(r *http.Request, e store.AuditEvent) {
	if err := s.store.InsertAudit(r.Context(), e); err != nil {
		s.logger.Error("auditoria: registrar negação", "action", e.Action, "err", err)
	}
}

// errAudit marca, dentro de uma transação, que o erro veio da gravação da
// auditoria (e não da operação), para o handler responder audit_failed.
var errAudit = errors.New("auditoria")

// auditErr embrulha o erro da gravação da auditoria com errAudit.
func auditErr(err error) error {
	if err != nil {
		return fmt.Errorf("%w: %w", errAudit, err)
	}
	return nil
}

// writeAuditFailed é a resposta da falha fechada (decisão 7): sem registro
// na auditoria, a operação não acontece.
func writeAuditFailed(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "audit_failed",
		"não foi possível registrar a auditoria; a operação foi cancelada")
}

type auditItem struct {
	At            time.Time `json:"at"`
	UserID        string    `json:"user_id,omitempty"`
	UserEmail     string    `json:"user_email,omitempty"`
	RemoteAddr    string    `json:"remote_addr,omitempty"`
	Action        string    `json:"action"`
	ProjectID     string    `json:"project_id,omitempty"`
	ProjectName   string    `json:"project_name,omitempty"`
	SecretKey     string    `json:"secret_key,omitempty"`
	SecretVersion int       `json:"secret_version,omitempty"`
	TargetUserID  string    `json:"target_user_id,omitempty"`
	TargetEmail   string    `json:"target_email,omitempty"`
	Role          string    `json:"role,omitempty"`
	Result        string    `json:"result"`
}

type auditResponse struct {
	Events []auditItem `json:"events"`
}

// handleListAudit devolve a trilha de auditoria, mais recente primeiro
// (superadmin e admin). ?project= filtra pelo nome do projeto e ?limit=
// limita a quantidade (padrão 100, máximo 1000).
func (s *server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit inválido (de 1 a 1000)")
			return
		}
		limit = n
	}
	events, err := s.store.ListAudit(r.Context(), store.AuditFilter{ProjectName: r.URL.Query().Get("project"), Limit: limit})
	if err != nil {
		s.logger.Error("ler auditoria", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	items := make([]auditItem, 0, len(events))
	for _, e := range events {
		items = append(items, auditItem(e))
	}
	writeJSON(w, http.StatusOK, auditResponse{Events: items})
}
