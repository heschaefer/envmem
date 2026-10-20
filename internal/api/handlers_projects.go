package api

import (
	"errors"
	"net/http"
	"regexp"

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
}

type listProjectsResponse struct {
	Projects []projectItem `json:"projects"`
}

type createProjectRequest struct {
	Name string `json:"name"`
}

// handleListProjects devolve os projetos. Até a Fatia 4 (autenticação),
// devolve todos e sem papel; depois, só os do usuário, com o papel dele.
func (s *server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.store.ListProjects(r.Context())
	if err != nil {
		s.logger.Error("listar projetos", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	items := make([]projectItem, 0, len(projects))
	for _, p := range projects {
		items = append(items, projectItem{ID: p.ID, Name: p.Name})
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

	p, err := s.store.CreateProject(r.Context(), req.Name)
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

	err := s.store.DeleteProject(r.Context(), name)
	switch {
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

// lookupProject busca o projeto da rota. Se não existir ou der erro, já
// escreve a resposta e devolve ok = false.
func (s *server) lookupProject(w http.ResponseWriter, r *http.Request) (p store.Project, ok bool) {
	name := r.PathValue("project")
	p, err := s.store.ProjectByName(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		writeProjectNotFound(w)
		return store.Project{}, false
	}
	if err != nil {
		s.logger.Error("ler projeto", "project", name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return store.Project{}, false
	}
	return p, true
}

func writeProjectNotFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "project_not_found", "projeto não encontrado")
}
