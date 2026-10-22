package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

type userItem struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	GlobalRole   string    `json:"global_role,omitempty"`
	TempPassword bool      `json:"temp_password"`
	CreatedAt    time.Time `json:"created_at"`
}

type listUsersResponse struct {
	Users []userItem `json:"users"`
}

type createUserRequest struct {
	Email        string `json:"email"`
	GlobalRole   string `json:"global_role"`
	TempPassword string `json:"temp_password"`
}

type resetPasswordRequest struct {
	TempPassword string `json:"temp_password"`
}

func userItemOf(u store.User) userItem {
	return userItem{ID: u.ID, Email: u.Email, GlobalRole: u.GlobalRole,
		TempPassword: u.TempPasswordExpiresAt != nil, CreatedAt: u.CreatedAt}
}

// handleListUsers lista os usuários (só superadmin). O hash da senha nunca
// sai do servidor.
func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.logger.Error("listar usuários", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	items := make([]userItem, 0, len(users))
	for _, u := range users {
		items = append(items, userItemOf(u))
	}
	writeJSON(w, http.StatusOK, listUsersResponse{Users: items})
}

// handleCreateUser cria um usuário com a senha temporária digitada pelo
// superadmin (decisão 43): troca obrigatória no primeiro login, validade de
// 72 horas.
func (s *server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body",
			`corpo JSON inválido (esperado {"email": "...", "global_role": "" | "admin" | "superadmin", "temp_password": "..."})`)
		return
	}
	password := []byte(req.TempPassword)
	defer clear(password)

	email, err := auth.NormalizeEmail(req.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_email", "e-mail inválido")
		return
	}
	if req.GlobalRole != "" && req.GlobalRole != store.RoleAdmin && req.GlobalRole != store.RoleSuperadmin {
		writeError(w, http.StatusBadRequest, "invalid_role", `papel global inválido (use "", "admin" ou "superadmin")`)
		return
	}
	if err := auth.CheckPasswordPolicy(password); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}

	u, err := s.store.CreateUser(r.Context(), email, req.GlobalRole, auth.HashPassword(password), s.now().Add(auth.TempPasswordTTL))
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "user_exists", "já existe um usuário com esse e-mail")
		return
	}
	if err != nil {
		s.logger.Error("criar usuário", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info("usuário criado", "user_id", u.ID, "global_role", u.GlobalRole)
	writeJSON(w, http.StatusCreated, userItemOf(u))
}

// handleDeleteUser remove um usuário (pelo id). Não remove o último
// superadmin, nem a si mesmo (para isso, outro superadmin o remove).
func (s *server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user")
	if id == sessionFrom(r.Context()).user.ID {
		writeError(w, http.StatusConflict, "cannot_remove_self", "não é possível remover a si mesmo; peça a outro superadmin")
		return
	}
	err := s.store.DeleteUser(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "user_not_found", "usuário não encontrado")
		return
	case errors.Is(err, store.ErrLastSuperadmin):
		writeError(w, http.StatusConflict, "last_superadmin", "não é possível remover o último superadmin")
		return
	case err != nil:
		s.logger.Error("remover usuário", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info("usuário removido", "user_id", id)
	w.WriteHeader(http.StatusNoContent)
}

// handleResetPassword define uma nova senha temporária para um usuário que
// esqueceu a dele (decisão 46) e revoga todas as sessões dele. Para a
// própria senha, o caminho é a troca de senha, que exige a senha atual.
func (s *server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user")
	if id == sessionFrom(r.Context()).user.ID {
		writeError(w, http.StatusConflict, "cannot_reset_self", "para a própria senha, use a troca de senha")
		return
	}
	var req resetPasswordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `corpo JSON inválido (esperado {"temp_password": "..."})`)
		return
	}
	password := []byte(req.TempPassword)
	defer clear(password)
	if err := auth.CheckPasswordPolicy(password); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}

	err := s.store.ResetPassword(r.Context(), id, auth.HashPassword(password), s.now().Add(auth.TempPasswordTTL))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user_not_found", "usuário não encontrado")
		return
	}
	if err != nil {
		s.logger.Error("redefinir senha", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info("senha redefinida", "user_id", id)
	w.WriteHeader(http.StatusNoContent)
}
