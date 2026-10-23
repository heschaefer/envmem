package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/heschaefer/envmem/internal/store"
)

// rbacEnv é um ambiente com o cofre aberto, os projetos demo e outro, e um
// usuário de cada papel: superadmin (o root do testEnv), admin, gestor e
// desenvolvedor do demo, e alguém de fora (sem papel global e sem projeto).
type rbacEnv struct {
	*testEnv
	tokens map[string]string // papel -> token
}

func newRBACEnv(t *testing.T) *rbacEnv {
	t.Helper()
	e := openEnv(t) // projeto demo
	outro := e.createProject(t, "outro")
	demo, _ := e.store.ProjectByName(t.Context(), "demo")
	re := &rbacEnv{testEnv: e, tokens: map[string]string{"superadmin": e.token}}

	users := []struct{ name, global, demoRole string }{
		{"admin", store.RoleAdmin, ""},
		{"gestor", "", store.RoleGestor},
		{"desenvolvedor", "", store.RoleDesenvolvedor},
		{"de-fora", "", ""},
	}
	for _, u := range users {
		email := u.name + "@empresa.com"
		created := e.store.addUser(store.User{Email: email, GlobalRole: u.global, PasswordHash: rootHash()})
		if u.demoRole != "" {
			e.store.setMember(demo.ID, created.ID, u.demoRole)
		}
		re.tokens[u.name] = e.sessionFor(t, email)
	}
	// O gestor do demo é desenvolvedor no outro: o papel vale por projeto.
	gestor, _ := e.store.UserByEmail(t.Context(), "gestor@empresa.com")
	e.store.setMember(outro.ID, gestor.ID, store.RoleDesenvolvedor)
	return re
}

// TestRouteRoleMatrix percorre cada rota com cada papel e compara com a
// tabela de papéis do CLAUDE.md e com a decisão 6 (403 para papel
// insuficiente; 404 para quem não é membro, igual a projeto inexistente).
func TestRouteRoleMatrix(t *testing.T) {
	e := newRBACEnv(t)
	roles := []string{"superadmin", "admin", "gestor", "desenvolvedor", "de-fora"}
	for _, role := range roles {
		e.createProject(t, "alvo-"+role) // um projeto para cada papel tentar apagar
	}

	const ok, forbidden, notFound = "ok", "403", "404"
	tests := []struct {
		method, path, body string
		want               map[string]string
	}{
		{"GET", "/v1/projects", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": ok, "de-fora": ok}},
		{"POST", "/v1/projects", `{"name":"novo-{role}"}`, map[string]string{
			"superadmin": ok, "admin": ok, "gestor": forbidden, "desenvolvedor": forbidden, "de-fora": forbidden}},
		{"DELETE", "/v1/projects/alvo-{role}", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": forbidden, "desenvolvedor": forbidden, "de-fora": forbidden}},
		{"GET", "/v1/projects/demo/secrets", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": ok, "de-fora": notFound}},
		{"PUT", "/v1/projects/demo/secrets/K_{ROLE}", `{"value":"v"}`, map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": forbidden, "de-fora": notFound}},
		// No outro, o gestor do demo é só desenvolvedor.
		{"PUT", "/v1/projects/outro/secrets/K_{ROLE}", `{"value":"v"}`, map[string]string{
			"superadmin": ok, "admin": ok, "gestor": forbidden, "desenvolvedor": notFound, "de-fora": notFound}},
		{"GET", "/v1/projects/demo/secrets/meta", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": ok, "de-fora": notFound}},
		{"GET", "/v1/projects/demo/secrets/K_{ROLE}", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": forbidden, "de-fora": notFound}},
		{"DELETE", "/v1/projects/demo/secrets/K_{ROLE}", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": forbidden, "de-fora": notFound}},
		{"POST", "/v1/projects/demo/secrets/K_{ROLE}/restore", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": forbidden, "de-fora": notFound}},
		{"DELETE", "/v1/projects/demo/secrets/K_{ROLE}", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": forbidden, "de-fora": notFound}},
		{"GET", "/v1/projects/demo/trash", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": forbidden, "de-fora": notFound}},
		{"DELETE", "/v1/projects/demo/trash/K_{ROLE}", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": forbidden, "desenvolvedor": forbidden, "de-fora": notFound}},
		{"GET", "/v1/projects/demo/members", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": ok, "desenvolvedor": forbidden, "de-fora": notFound}},
		{"GET", "/v1/audit", "", map[string]string{
			"superadmin": ok, "admin": ok, "gestor": forbidden, "desenvolvedor": forbidden, "de-fora": forbidden}},
		{"GET", "/v1/users", "", map[string]string{
			"superadmin": ok, "admin": forbidden, "gestor": forbidden, "desenvolvedor": forbidden, "de-fora": forbidden}},
		{"POST", "/v1/users", `{"email":"novo-{role}@empresa.com","temp_password":"senha temporaria longa"}`, map[string]string{
			"superadmin": ok, "admin": forbidden, "gestor": forbidden, "desenvolvedor": forbidden, "de-fora": forbidden}},
		// Por último: depois do seal do superadmin, o cofre fica selado.
		{"POST", "/v1/seal", "", map[string]string{
			"superadmin": ok, "admin": forbidden, "gestor": forbidden, "desenvolvedor": forbidden, "de-fora": forbidden}},
	}

	for _, tt := range tests {
		for _, role := range roles {
			r := strings.NewReplacer("{role}", role, "{ROLE}", strings.ToUpper(strings.ReplaceAll(role, "-", "_")))
			path, body := r.Replace(tt.path), r.Replace(tt.body)
			rec := e.doAs(t, e.tokens[role], tt.method, path, body)

			var got string
			switch {
			case rec.Code == http.StatusForbidden:
				got = forbidden
			case rec.Code == http.StatusNotFound:
				got = notFound
			case rec.Code < 300:
				got = ok
			default:
				got = rec.Body.String()
			}
			if got != tt.want[role] {
				t.Errorf("%s %s como %s: %s (status %d), quero %s", tt.method, path, role, got, rec.Code, tt.want[role])
			}
		}
	}
}

// Para quem não é membro, um projeto que existe e um que não existe dão a
// mesma resposta: não dá para descobrir quais projetos existem.
func TestNonMemberCannotTellProjectExists(t *testing.T) {
	e := newRBACEnv(t)
	exists := e.doAs(t, e.tokens["de-fora"], http.MethodGet, "/v1/projects/demo/secrets", "")
	missing := e.doAs(t, e.tokens["de-fora"], http.MethodGet, "/v1/projects/nao-existe/secrets", "")
	if exists.Code != http.StatusNotFound || exists.Body.String() != missing.Body.String() {
		t.Fatalf("respostas diferentes: %d %s / %d %s", exists.Code, exists.Body, missing.Code, missing.Body)
	}
}

// Cada um vê só os próprios projetos, com o papel em cada um.
func TestListProjectsIsFiltered(t *testing.T) {
	e := newRBACEnv(t)
	list := func(role string) []projectItem {
		return decode[listProjectsResponse](t, e.doAs(t, e.tokens[role], http.MethodGet, "/v1/projects", "")).Projects
	}

	if got := list("desenvolvedor"); len(got) != 1 || got[0].Name != "demo" || got[0].Role != "desenvolvedor" {
		t.Errorf("desenvolvedor vê %+v", got)
	}
	if got := list("gestor"); len(got) != 2 || got[0].Role != "gestor" || got[1].Name != "outro" || got[1].Role != "desenvolvedor" {
		t.Errorf("gestor vê %+v", got)
	}
	if got := list("de-fora"); len(got) != 0 {
		t.Errorf("de fora vê %+v", got)
	}
	if got := list("admin"); len(got) != 2 || got[0].Role != "admin" {
		t.Errorf("admin vê %+v", got)
	}
}
