package api

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

// projectNameRE é o formato do nome de projeto: minúsculas, dígitos e
// hífen, começando por letra ou dígito, até 63 caracteres. O nome aparece
// na URL e no terminal, então fica restrito a caracteres que não precisam
// de escape. A migração 00002 tem o mesmo CHECK no banco.
var projectNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type projectItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role,omitempty"` // papel de quem pediu a lista
}

type listProjectsResponse struct {
	Projects []projectItem `json:"projects"`
}

type createProjectRequest struct {
	Name string `json:"name"`
}

// handleListProjects devolve os projetos de quem pediu, com o papel em cada
// um: superadmin e admin veem todos (com o papel global); os demais, só os
// projetos de que são membros. Os outros nem aparecem (decisão 6).
func (s *server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	user := sessionFrom(r.Context()).user
	items := []projectItem{}

	if role := auth.GlobalRole(user.GlobalRole); role != auth.RoleUser {
		projects, err := s.store.ListProjects(r.Context())
		if err != nil {
			s.logger.Error("listar projetos", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "erro interno")
			return
		}
		for _, p := range projects {
			items = append(items, projectItem{ID: p.ID, Name: p.Name, Role: string(role)})
		}
	} else {
		memberships, err := s.store.ProjectsForMember(r.Context(), user.ID)
		if err != nil {
			s.logger.Error("listar projetos do usuário", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "erro interno")
			return
		}
		for _, m := range memberships {
			items = append(items, projectItem{ID: m.ID, Name: m.Name, Role: m.Role})
		}
	}
	writeJSON(w, http.StatusOK, listProjectsResponse{Projects: items})
}

// handleCreateProject cria um projeto ({"name": "..."}). Não depende do
// cofre: criar um projeto não cifra nada.
func (s *server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req createProjectRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `corpo JSON inválido (esperado {"name": "..."})`)
		return
	}
	if !projectNameRE.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, "invalid_project_name",
			"nome de projeto inválido: use minúsculas, dígitos e hífen, começando por letra ou dígito (até 63 caracteres)")
		return
	}

	var p store.Project
	err := s.store.InTx(r.Context(), func(tx Store) error {
		var err error
		if p, err = tx.CreateProject(r.Context(), req.Name); err != nil {
			return err
		}
		e := s.event(r, "project.create", store.AuditSuccess)
		e.ProjectID, e.ProjectName = p.ID, p.Name
		return auditErr(tx.InsertAudit(r.Context(), e))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: registrar criação de projeto", "err", err)
		writeAuditFailed(w)
		return
	}
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "project_exists", "já existe um projeto com esse nome")
		return
	}
	if err != nil {
		s.logger.Error("criar projeto", "project", req.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	s.logger.Info("projeto criado", "project", p.Name, "project_id", p.ID)
	writeJSON(w, http.StatusCreated, projectItem{ID: p.ID, Name: p.Name})
}

// handleDeleteProject apaga um projeto vazio. Com segredos, responde 409:
// o que fazer com eles (apagar de vez ou marcar como removidos) é a
// decisão 11, ainda em aberto.
func (s *server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("project")

	err := s.store.InTx(r.Context(), func(tx Store) error {
		if err := tx.DeleteProject(r.Context(), name); err != nil {
			return err
		}
		e := s.event(r, "project.delete", store.AuditSuccess)
		e.ProjectName = name
		return auditErr(tx.InsertAudit(r.Context(), e))
	})
	switch {
	case errors.Is(err, errAudit):
		s.logger.Error("auditoria: registrar remoção de projeto", "err", err)
		writeAuditFailed(w)
		return
	case errors.Is(err, store.ErrNotFound):
		writeProjectNotFound(w)
		return
	case errors.Is(err, store.ErrProjectNotEmpty):
		writeError(w, http.StatusConflict, "project_not_empty", "o projeto ainda tem segredos; remova-os antes")
		return
	case err != nil:
		s.logger.Error("apagar projeto", "project", name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	s.logger.Info("projeto apagado", "project", name)
	w.WriteHeader(http.StatusNoContent)
}
