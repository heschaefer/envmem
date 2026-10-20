package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestCreateAndListProjects(t *testing.T) {
	e := newTestEnv(t)

	// Projetos não dependem do cofre: funcionam com ele selado.
	created := e.createProject(t, "app-prod")
	if created.ID == "" || created.Name != "app-prod" {
		t.Fatalf("resposta do POST = %+v", created)
	}
	e.createProject(t, "app-homo")

	rec := e.do(t, http.MethodGet, "/v1/projects", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	got := decode[listProjectsResponse](t, rec).Projects
	if len(got) != 2 || got[0].Name != "app-homo" || got[1].Name != "app-prod" {
		t.Fatalf("projetos = %+v, quero app-homo e app-prod em ordem", got)
	}
}

func TestListProjectsEmpty(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(t, http.MethodGet, "/v1/projects", "")
	if strings.TrimSpace(rec.Body.String()) != `{"projects":[]}` {
		t.Fatalf("corpo = %s, quero lista vazia (não null)", rec.Body.String())
	}
}

func TestCreateProjectRejects(t *testing.T) {
	e := newTestEnv(t)
	e.createProject(t, "demo")

	wantError(t, e.do(t, http.MethodPost, "/v1/projects", `{"name":"demo"}`), http.StatusConflict, "project_exists")
	wantError(t, e.do(t, http.MethodPost, "/v1/projects", `{"nome":"x"}`), http.StatusBadRequest, "invalid_body")
	for _, name := range []string{"", "Demo", "-demo", "a_b", "a b", "a/b", "..", strings.Repeat("a", 64)} {
		wantError(t, e.do(t, http.MethodPost, "/v1/projects", `{"name":"`+name+`"}`),
			http.StatusBadRequest, "invalid_project_name")
	}
	if len(e.store.projects) != 1 {
		t.Fatalf("só o demo deveria existir: %+v", e.store.projects)
	}
}

func TestDeleteProject(t *testing.T) {
	e := openEnv(t) // cofre aberto e projeto demo criado
	e.createProject(t, "vazio")

	if rec := e.do(t, http.MethodDelete, "/v1/projects/vazio", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE vazio: %d %s", rec.Code, rec.Body.String())
	}
	wantError(t, e.do(t, http.MethodDelete, "/v1/projects/vazio", ""), http.StatusNotFound, "project_not_found")

	// Com segredos, o DELETE é recusado (decisão 11 em aberto) e nada some.
	e.put(t, "demo", "DB_PASSWORD", "x")
	wantError(t, e.do(t, http.MethodDelete, "/v1/projects/demo", ""), http.StatusConflict, "project_not_empty")
	if rec := e.do(t, http.MethodGet, secretPath, ""); rec.Code != http.StatusOK {
		t.Fatalf("o projeto demo deveria continuar acessível: %d", rec.Code)
	}
}
