package api

import (
	"errors"
	"net/http"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

type memberItem struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

type listMembersResponse struct {
	Members []memberItem `json:"members"`
}

type setMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// handleListMembers lista os membros do projeto.
func (s *server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	project := projectFrom(r.Context()).project
	members, err := s.store.ListMembers(r.Context(), project.ID)
	if err != nil {
		s.logger.Error("listar membros", "project", project.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	items := make([]memberItem, 0, len(members))
	for _, m := range members {
		items = append(items, memberItem{UserID: m.UserID, Email: m.Email, Role: m.Role})
	}
	writeJSON(w, http.StatusOK, listMembersResponse{Members: items})
}

// handleSetMember adiciona um membro ao projeto ou troca o papel dele
// ({"email": "...", "role": "gestor" | "desenvolvedor"}).
//
// A rota exige gerenciar membros (gestor, admin, superadmin). O que depende
// do corpo é conferido aqui (decisão 5): só admin e superadmin nomeiam
// gestores, e um gestor não mexe no papel de outro gestor.
func (s *server) handleSetMember(w http.ResponseWriter, r *http.Request) {
	access := projectFrom(r.Context())
	var req setMemberRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `corpo JSON inválido (esperado {"email": "...", "role": "gestor" | "desenvolvedor"})`)
		return
	}
	if req.Role != store.RoleGestor && req.Role != store.RoleDesenvolvedor {
		writeError(w, http.StatusBadRequest, "invalid_role", `papel inválido (use "gestor" ou "desenvolvedor")`)
		return
	}
	email, err := auth.NormalizeEmail(req.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_email", "e-mail inválido")
		return
	}

	user, err := s.store.UserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user_not_found", "usuário não encontrado")
		return
	}
	if err != nil {
		s.logger.Error("ler usuário", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	if !s.canChangeMember(w, r, access, user.ID, req.Role) {
		return
	}

	err = s.store.InTx(r.Context(), func(tx Store) error {
		if err := tx.SetMember(r.Context(), access.project.ID, user.ID, req.Role); err != nil {
			return err
		}
		e := s.event(r, "member.set", store.AuditSuccess)
		e.TargetUserID, e.TargetEmail, e.Role = user.ID, user.Email, req.Role
		return auditErr(tx.InsertAudit(r.Context(), e))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: registrar membro", "err", err)
		writeAuditFailed(w)
		return
	}
	if err != nil {
		s.logger.Error("gravar membro", "project", access.project.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info("membro gravado", "project", access.project.Name, "user_id", user.ID, "role", req.Role)
	writeJSON(w, http.StatusOK, memberItem{UserID: user.ID, Email: user.Email, Role: req.Role})
}

// handleRemoveMember tira um usuário (pelo id) do projeto.
func (s *server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	access := projectFrom(r.Context())
	userID := r.PathValue("user")
	if !s.canChangeMember(w, r, access, userID, "") {
		return
	}
	err := s.store.InTx(r.Context(), func(tx Store) error {
		if err := tx.RemoveMember(r.Context(), access.project.ID, userID); err != nil {
			return err
		}
		e := s.event(r, "member.remove", store.AuditSuccess)
		e.TargetUserID = userID
		if u, err := tx.UserByID(r.Context(), userID); err == nil {
			e.TargetEmail = u.Email
		}
		return auditErr(tx.InsertAudit(r.Context(), e))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: registrar remoção de membro", "err", err)
		writeAuditFailed(w)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "member_not_found", "o usuário não é membro deste projeto")
		return
	}
	if err != nil {
		s.logger.Error("remover membro", "project", access.project.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info("membro removido", "project", access.project.Name, "user_id", userID)
	w.WriteHeader(http.StatusNoContent)
}

// canChangeMember aplica as regras que dependem do corpo ou do alvo: mexer
// num gestor (nomear, rebaixar ou remover) exige nomear gestores, que só
// admin e superadmin têm. newRole vazio é remoção. Se não puder, já
// responde 403.
func (s *server) canChangeMember(w http.ResponseWriter, r *http.Request, access projectAccess, userID, newRole string) bool {
	if auth.PermNominateManagers.Allows(access.role) {
		return true
	}
	current, err := s.store.MemberRole(r.Context(), access.project.ID, userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("ler papel do membro", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return false
	}
	if newRole == store.RoleGestor || current == store.RoleGestor {
		writeError(w, http.StatusForbidden, "forbidden", "só admin e superadmin nomeiam, rebaixam ou removem gestores")
		return false
	}
	return true
}
