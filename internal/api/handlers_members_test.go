package api

import (
	"net/http"
	"testing"

	"github.com/heschaefer/envmem/internal/store"
)

func TestMembers(t *testing.T) {
	e := newRBACEnv(t)
	e.store.addUser(store.User{Email: "novo@empresa.com", PasswordHash: rootHash()})
	gestor := e.tokens["gestor"]
	members := "/v1/projects/demo/members"

	// O gestor adiciona desenvolvedores...
	rec := e.doAs(t, gestor, http.MethodPost, members, `{"email":"Novo@Empresa.com","role":"desenvolvedor"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("gestor adiciona desenvolvedor: %d %s", rec.Code, rec.Body.String())
	}
	novo := decode[memberItem](t, rec)
	// ...mas não nomeia gestor, nem rebaixa ou remove outro gestor.
	wantError(t, e.doAs(t, gestor, http.MethodPost, members, `{"email":"novo@empresa.com","role":"gestor"}`), http.StatusForbidden, "forbidden")
	gestorUser, _ := e.store.UserByEmail(t.Context(), "gestor@empresa.com")
	wantError(t, e.doAs(t, gestor, http.MethodPost, members, `{"email":"gestor@empresa.com","role":"desenvolvedor"}`), http.StatusForbidden, "forbidden")
	wantError(t, e.doAs(t, gestor, http.MethodDelete, members+"/"+gestorUser.ID, ""), http.StatusForbidden, "forbidden")

	// O admin nomeia gestor.
	if rec := e.doAs(t, e.tokens["admin"], http.MethodPost, members, `{"email":"novo@empresa.com","role":"gestor"}`); rec.Code != http.StatusOK {
		t.Fatalf("admin nomeia gestor: %d %s", rec.Code, rec.Body.String())
	}
	list := decode[listMembersResponse](t, e.doAs(t, gestor, http.MethodGet, members, "")).Members
	if len(list) != 3 {
		t.Fatalf("membros = %+v", list)
	}

	// Erros de entrada.
	wantError(t, e.doAs(t, gestor, http.MethodPost, members, `{"email":"ninguem@empresa.com","role":"desenvolvedor"}`), http.StatusNotFound, "user_not_found")
	wantError(t, e.doAs(t, gestor, http.MethodPost, members, `{"email":"novo@empresa.com","role":"admin"}`), http.StatusBadRequest, "invalid_role")
	wantError(t, e.doAs(t, gestor, http.MethodDelete, members+"/nao-e-um-id", ""), http.StatusNotFound, "member_not_found")

	// O admin rebaixa e remove; o desenvolvedor removido perde o acesso.
	if rec := e.doAs(t, e.tokens["admin"], http.MethodDelete, members+"/"+novo.UserID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("admin remove: %d %s", rec.Code, rec.Body.String())
	}
	dev, _ := e.store.UserByEmail(t.Context(), "desenvolvedor@empresa.com")
	if rec := e.doAs(t, gestor, http.MethodDelete, members+"/"+dev.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("gestor remove desenvolvedor: %d", rec.Code)
	}
	wantError(t, e.doAs(t, e.tokens["desenvolvedor"], http.MethodGet, secretPath, ""), http.StatusNotFound, "project_not_found")
}
