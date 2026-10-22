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

// O login identifica o usuário só se o e-mail existir: o texto digitado
// num e-mail inexistente não é guardado.
func TestAuditLogin(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "dev@empresa.com", testPassword, 0)
	e.store.audit = nil

	e.login(t, "dev@empresa.com", "senha errada mas longa")
	e.login(t, "senha-digitada-no-campo-errado", testPassword)
	e.tokenFor(t, "dev@empresa.com", testPassword)

	ev := e.store.audit
	if len(ev) != 3 {
		t.Fatalf("eventos = %+v", ev)
	}
	if ev[0].Action != "auth.login" || ev[0].Result != store.AuditFailure || ev[0].UserEmail != "dev@empresa.com" {
		t.Errorf("senha errada = %+v", ev[0])
	}
	if ev[1].Result != store.AuditFailure || ev[1].UserID != "" || ev[1].UserEmail != "" {
		t.Errorf("e-mail inexistente = %+v", ev[1])
	}
	if ev[2].Result != store.AuditSuccess || ev[2].UserEmail != "dev@empresa.com" {
		t.Errorf("sucesso = %+v", ev[2])
	}
	for _, x := range ev {
		if strings.Contains(x.UserEmail+x.TargetEmail, "senha-digitada") {
			t.Fatalf("o texto digitado foi guardado: %+v", x)
		}
	}
}

// Fluxo administrativo completo: cada passo deixa um evento.
func TestAuditAdminActions(t *testing.T) {
	e := openEnv(t)
	e.store.audit = nil

	u := decode[userItem](t, e.do(t, http.MethodPost, "/v1/users", `{"email":"dev@empresa.com","temp_password":"temporaria bem longa"}`))
	e.do(t, http.MethodPost, "/v1/projects/demo/members", `{"email":"dev@empresa.com","role":"desenvolvedor"}`)
	e.do(t, http.MethodDelete, "/v1/projects/demo/members/"+u.ID, "")
	e.do(t, http.MethodPost, "/v1/users/"+u.ID+"/password/reset", `{"temp_password":"outra temporaria longa"}`)
	e.do(t, http.MethodDelete, "/v1/users/"+u.ID, "")
	e.createProject(t, "temp")
	e.do(t, http.MethodDelete, "/v1/projects/temp", "")
	e.do(t, http.MethodPost, "/v1/seal", "")

	want := []string{"user.create:success", "member.set:success", "member.remove:success",
		"user.password_reset:success", "user.delete:success", "project.create:success",
		"project.delete:success", "vault.seal:success"}
	if got := e.store.actions(); !slices.Equal(got, want) {
		t.Fatalf("ações = %q\nquero   %q", got, want)
	}
	// O usuário afetado fica registrado pelo id e pelo e-mail.
	for _, ev := range e.store.audit[:5] {
		if ev.TargetUserID != u.ID || ev.TargetEmail != "dev@empresa.com" || ev.UserEmail != "root@empresa.com" {
			t.Errorf("%s: alvo = %q %q, autor = %q", ev.Action, ev.TargetUserID, ev.TargetEmail, ev.UserEmail)
		}
	}
	if e.store.audit[1].Role != "desenvolvedor" || e.store.audit[1].ProjectName != "demo" {
		t.Errorf("member.set = %+v", e.store.audit[1])
	}
}

func TestAuditVault(t *testing.T) {
	e := newTestEnv(t)
	e.store.audit = nil // o login do superadmin do ambiente
	key := vaultKey(t)
	e.unseal(t, key)
	e.vault.Seal()
	e.unseal(t, vaultKey(t)) // chave errada
	got := e.store.actions()
	if !slices.Equal(got, []string{"vault.unseal:success", "vault.unseal:failure"}) {
		t.Fatalf("ações = %q", got)
	}
	if ev := e.store.audit[1]; ev.UserID != "" || ev.RemoteAddr != "192.0.2.1" {
		t.Errorf("unseal sem sessão: %+v", ev)
	}
}

// Falha fechada nas ações que dão acesso; seal e logout são a exceção.
func TestAuditFailClosedOnAccessChanges(t *testing.T) {
	e := openEnv(t)
	e.addUser(t, "dev@empresa.com", testPassword, 0)
	devToken := e.tokenFor(t, "dev@empresa.com", testPassword)
	e.store.failAudit = true

	// Login: sem registro, sem sessão.
	wantError(t, e.login(t, "dev@empresa.com", testPassword), http.StatusInternalServerError, "audit_failed")
	// Projeto, usuário e membro: nada fica gravado.
	wantError(t, e.do(t, http.MethodPost, "/v1/projects", `{"name":"novo"}`), http.StatusInternalServerError, "audit_failed")
	wantError(t, e.do(t, http.MethodPost, "/v1/users", `{"email":"x@empresa.com","temp_password":"temporaria bem longa"}`), http.StatusInternalServerError, "audit_failed")
	wantError(t, e.do(t, http.MethodPost, "/v1/projects/demo/members", `{"email":"dev@empresa.com","role":"desenvolvedor"}`), http.StatusInternalServerError, "audit_failed")
	if _, err := e.store.ProjectByName(t.Context(), "novo"); err == nil {
		t.Error("projeto criado sem auditoria")
	}
	if _, err := e.store.UserByEmail(t.Context(), "x@empresa.com"); err == nil {
		t.Error("usuário criado sem auditoria")
	}
	if list, _ := e.store.ListMembers(t.Context(), "id-1"); len(list) != 0 {
		t.Errorf("membro gravado sem auditoria: %+v", list)
	}

	// Logout: a sessão cai mesmo sem registro.
	if rec := e.doAs(t, devToken, http.MethodPost, "/v1/auth/logout", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("logout sem auditoria: %d", rec.Code)
	}
	e.store.failAudit = false
	wantError(t, e.doAs(t, devToken, http.MethodGet, "/v1/auth/me", ""), http.StatusUnauthorized, "unauthorized")
	e.store.failAudit = true

	// Seal: o cofre fica selado mesmo sem registro.
	if rec := e.do(t, http.MethodPost, "/v1/seal", ""); rec.Code != http.StatusOK || !e.vault.Sealed() {
		t.Fatalf("seal sem auditoria: %d, selado = %v", rec.Code, e.vault.Sealed())
	}
	// Unseal: sem registro, o cofre volta a ficar selado.
	wantError(t, e.unseal(t, e.key), http.StatusInternalServerError, "audit_failed")
	if !e.vault.Sealed() {
		t.Fatal("o cofre ficou aberto sem auditoria do unseal")
	}
}
