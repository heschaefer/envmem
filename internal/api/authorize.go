package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

// projectAccess é o projeto da rota e o papel de quem faz a requisição
// nele, já conferidos por authorize.
type projectAccess struct {
	project store.Project
	role    auth.Role
}

type projectAccessKey struct{}

// projectFrom devolve o projeto da rota, gravado no contexto por authorize.
func projectFrom(ctx context.Context) projectAccess {
	pa, _ := ctx.Value(projectAccessKey{}).(projectAccess)
	return pa
}

// authorize confere se quem fez a requisição (já autenticado por
// requireAuth) tem a permissão p (decisões 5 e 6):
//
//   - permissão global: vale o papel global; sem ela, 403;
//   - permissão de projeto: resolve o projeto da rota e o papel nele.
//     Quem não é membro (nem superadmin ou admin) recebe 404, a mesma
//     resposta de um projeto inexistente, para não revelar que ele existe.
//     Quem é membro mas não tem o papel exigido recebe 403: ele já sabe que
//     o projeto existe, então nada vaza.
func (s *server) authorize(p auth.Permission, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := sessionFrom(r.Context()).user
		if !p.Project {
			if !p.Allows(auth.GlobalRole(user.GlobalRole)) {
				writeForbidden(w)
				return
			}
			next(w, r)
			return
		}

		name := r.PathValue("project")
		project, err := s.store.ProjectByName(r.Context(), name)
		if errors.Is(err, store.ErrNotFound) {
			writeProjectNotFound(w)
			return
		}
		if err != nil {
			s.logger.Error("ler projeto", "project", name, "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "erro interno")
			return
		}

		var memberRole string
		if auth.GlobalRole(user.GlobalRole) == auth.RoleUser {
			memberRole, err = s.store.MemberRole(r.Context(), project.ID, user.ID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.logger.Error("ler papel no projeto", "project", name, "err", err)
				writeError(w, http.StatusInternalServerError, "internal", "erro interno")
				return
			}
		}
		role, ok := auth.ProjectRole(user.GlobalRole, memberRole)
		if !ok {
			writeProjectNotFound(w)
			return
		}
		if !p.Allows(role) {
			writeForbidden(w)
			return
		}
		ctx := context.WithValue(r.Context(), projectAccessKey{}, projectAccess{project: project, role: role})
		next(w, r.WithContext(ctx))
	}
}

func writeForbidden(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "forbidden", "seu papel não permite esta ação")
}

// writeProjectNotFound é a resposta tanto para projeto inexistente quanto
// para projeto de que a pessoa não é membro (decisão 6): mesma mensagem,
// mesmo código.
func writeProjectNotFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "project_not_found", "projeto não encontrado ou sem acesso")
}
