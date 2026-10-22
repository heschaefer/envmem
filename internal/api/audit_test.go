package api

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/heschaefer/envmem/internal/store"
)

func TestAuditSecretEvents(t *testing.T) {
	e := openEnv(t)
	e.put(t, "demo", "DB_PASSWORD", "valor-1")
	e.put(t, "demo", "DB_PASSWORD", "valor-2")
	e.put(t, "demo", "API_KEY", "chave")
	e.do(t, http.MethodGet, secretPath, "")
	e.do(t, http.MethodGet, secretPath+"/DB_PASSWORD?version=1", "")

	var run []store.AuditEvent
	for _, ev := range e.store.audit {
		if ev.Action == "secret.run" {
			run = append(run, ev)
		}
	}
	// Uma linha por segredo entregue no run, com a versão entregue.
	if len(run) != 2 || run[0].SecretKey != "API_KEY" || run[1].SecretKey != "DB_PASSWORD" || run[1].SecretVersion != 2 {
		t.Fatalf("eventos do run = %+v", run)
	}
	ev := run[1]
	if ev.UserEmail != "root@empresa.com" || ev.ProjectName != "demo" || ev.ProjectID == "" || ev.RemoteAddr != "192.0.2.1" || ev.Result != store.AuditSuccess {
		t.Errorf("evento = %+v", ev)
	}
	last := e.store.audit[len(e.store.audit)-1]
	if last.Action != "secret.read" || last.SecretKey != "DB_PASSWORD" || last.SecretVersion != 1 {
		t.Errorf("leitura isolada = %+v", last)
	}
	// A auditoria registra chaves e versões, nunca valores.
	for _, ev := range e.store.audit {
		if strings.Contains(strings.Join([]string{ev.SecretKey, ev.ProjectName, ev.Action, ev.UserEmail}, " "), "valor-") {
			t.Fatalf("valor na auditoria: %+v", ev)
		}
	}
}

// Falha fechada na leitura: sem registro, nenhum valor sai do servidor.
func TestAuditFailClosedOnRead(t *testing.T) {
	e := openEnv(t)
	e.put(t, "demo", "DB_PASSWORD", "nao-pode-sair")
	e.store.failAudit = true

	for _, path := range []string{secretPath, secretPath + "/DB_PASSWORD"} {
		rec := e.do(t, http.MethodGet, path, "")
		if strings.Contains(rec.Body.String(), "nao-pode-sair") {
			t.Fatalf("%s entregou o valor sem auditoria", path)
		}
		wantError(t, rec, http.StatusInternalServerError, "audit_failed")
	}
}

// Falha fechada na escrita: a alteração é desfeita junto com o evento.
func TestAuditFailClosedOnWrite(t *testing.T) {
	e := openEnv(t)
	e.put(t, "demo", "EXISTE", "x")
	e.store.failAudit = true

	wantError(t, e.put(t, "demo", "NOVO", "x"), http.StatusInternalServerError, "audit_failed")
	wantError(t, e.do(t, http.MethodDelete, secretPath+"/EXISTE", ""), http.StatusInternalServerError, "audit_failed")

	e.store.failAudit = false
	names := decode[secretsMetaResponse](t, e.do(t, http.MethodGet, secretPath+"/meta", "")).Secrets
	if len(names) != 1 || names[0].Key != "EXISTE" {
		t.Fatalf("as escritas sem auditoria deveriam ter sido desfeitas: %+v", names)
	}
}

func TestAuditDenials(t *testing.T) {
	e := newRBACEnv(t)
	e.doAs(t, e.tokens["desenvolvedor"], http.MethodPut, secretPath+"/K", `{"value":"x"}`)
	e.doAs(t, e.tokens["de-fora"], http.MethodGet, secretPath, "")
	e.doAs(t, e.tokens["de-fora"], http.MethodGet, "/v1/projects/nao-existe/secrets", "")
	e.doAs(t, e.tokens["gestor"], http.MethodPost, "/v1/projects", `{"name":"x"}`)

	var denied []store.AuditEvent
	for _, ev := range e.store.audit {
		if ev.Result == store.AuditDenied {
			denied = append(denied, ev)
		}
	}
	if len(denied) != 4 {
		t.Fatalf("negações = %+v", denied)
	}
	want := []struct{ action, email, project string }{
		{"secrets.write", "desenvolvedor@empresa.com", "demo"},
		{"secrets.use", "de-fora@empresa.com", "demo"},
		{"secrets.use", "de-fora@empresa.com", "nao-existe"},
		{"projects.manage", "gestor@empresa.com", ""},
	}
	for i, w := range want {
		if d := denied[i]; d.Action != w.action || d.UserEmail != w.email || d.ProjectName != w.project {
			t.Errorf("negação %d = %+v, quero %+v", i, d, w)
		}
	}
	// O projeto que existe fica com o id; o inexistente, só com o nome pedido.
	if denied[1].ProjectID == "" || denied[2].ProjectID != "" {
		t.Errorf("ids: %q / %q", denied[1].ProjectID, denied[2].ProjectID)
	}
}

func TestListAudit(t *testing.T) {
	e := newRBACEnv(t)
	e.put(t, "demo", "K", "x")
	e.put(t, "outro", "K", "x")

	events := decode[auditResponse](t, e.doAs(t, e.tokens["admin"], http.MethodGet, "/v1/audit?project=demo", "")).Events
	if len(events) == 0 || slices.ContainsFunc(events, func(ev auditItem) bool { return ev.ProjectName != "demo" }) {
		t.Fatalf("filtro por projeto: %+v", events)
	}
	if got := decode[auditResponse](t, e.doAs(t, e.tokens["admin"], http.MethodGet, "/v1/audit?limit=1", "")).Events; len(got) != 1 || got[0].ProjectName != "outro" {
		t.Fatalf("limit=1 deveria trazer o mais recente: %+v", got)
	}
	wantError(t, e.doAs(t, e.tokens["admin"], http.MethodGet, "/v1/audit?limit=0", ""), http.StatusBadRequest, "invalid_limit")
	wantError(t, e.doAs(t, e.tokens["gestor"], http.MethodGet, "/v1/audit", ""), http.StatusForbidden, "forbidden")
}
