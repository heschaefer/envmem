package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/heschaefer/envmem/internal/auth"
)

func TestCreateUserWithTempPassword(t *testing.T) {
	e := newTestEnv(t)
	rec := e.do(t, http.MethodPost, "/v1/users",
		`{"email":"Nova@Empresa.com","global_role":"","temp_password":"temporaria bem longa"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("criar: %d %s", rec.Code, rec.Body.String())
	}
	u := decode[userItem](t, rec)
	if u.Email != "nova@empresa.com" || u.GlobalRole != "" || !u.TempPassword {
		t.Fatalf("usuário = %+v", u)
	}

	// Entra com a senha temporária, que vence em 72 horas.
	if !decode[loginResponse](t, e.login(t, "nova@empresa.com", "temporaria bem longa")).MustChangePassword {
		t.Error("o login deveria exigir a troca de senha")
	}
	e.clock.add(auth.TempPasswordTTL)
	wantError(t, e.login(t, "nova@empresa.com", "temporaria bem longa"), http.StatusUnauthorized, "temp_password_expired")
	// 72 horas depois, a sessão (8 horas) do superadmin também venceu.
	e.token = e.sessionFor(t, "root@empresa.com")

	// A listagem nunca mostra o hash.
	body := e.do(t, http.MethodGet, "/v1/users", "").Body.String()
	if strings.Contains(body, "argon2") || strings.Contains(body, "password_hash") {
		t.Fatalf("a listagem expõe o hash: %s", body)
	}

	wantError(t, e.do(t, http.MethodPost, "/v1/users", `{"email":"nova@empresa.com","temp_password":"temporaria bem longa"}`), http.StatusConflict, "user_exists")
	wantError(t, e.do(t, http.MethodPost, "/v1/users", `{"email":"x@empresa.com","global_role":"gestor","temp_password":"temporaria bem longa"}`), http.StatusBadRequest, "invalid_role")
	wantError(t, e.do(t, http.MethodPost, "/v1/users", `{"email":"x@empresa.com","temp_password":"curta"}`), http.StatusBadRequest, "invalid_password")
	wantError(t, e.do(t, http.MethodPost, "/v1/users", `{"email":"sem arroba","temp_password":"temporaria bem longa"}`), http.StatusBadRequest, "invalid_email")
}

func TestDeleteUser(t *testing.T) {
	e := newTestEnv(t)
	root, _ := e.store.UserByEmail(t.Context(), "root@empresa.com")
	other := decode[userItem](t, e.do(t, http.MethodPost, "/v1/users",
		`{"email":"super2@empresa.com","global_role":"superadmin","temp_password":"temporaria bem longa"}`))

	wantError(t, e.do(t, http.MethodDelete, "/v1/users/"+root.ID, ""), http.StatusConflict, "cannot_remove_self")
	if rec := e.do(t, http.MethodDelete, "/v1/users/"+other.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("remover: %d %s", rec.Code, rec.Body.String())
	}
	wantError(t, e.do(t, http.MethodDelete, "/v1/users/"+other.ID, ""), http.StatusNotFound, "user_not_found")
}

func TestResetPassword(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "dev@empresa.com", testPassword, 0)
	dev, _ := e.store.UserByEmail(t.Context(), "dev@empresa.com")
	devToken := e.tokenFor(t, "dev@empresa.com", testPassword)

	reset := `{"temp_password":"nova temporaria longa"}`
	if rec := e.do(t, http.MethodPost, "/v1/users/"+dev.ID+"/password/reset", reset); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	// As sessões abertas caem; a senha antiga não entra; a nova é temporária.
	wantError(t, e.doAs(t, devToken, http.MethodGet, "/v1/auth/me", ""), http.StatusUnauthorized, "unauthorized")
	wantError(t, e.login(t, "dev@empresa.com", testPassword), http.StatusUnauthorized, "invalid_credentials")
	if !decode[loginResponse](t, e.login(t, "dev@empresa.com", "nova temporaria longa")).MustChangePassword {
		t.Error("a senha redefinida deveria ser temporária")
	}

	root, _ := e.store.UserByEmail(t.Context(), "root@empresa.com")
	wantError(t, e.do(t, http.MethodPost, "/v1/users/"+root.ID+"/password/reset", reset), http.StatusConflict, "cannot_reset_self")
	wantError(t, e.do(t, http.MethodPost, "/v1/users/inexistente/password/reset", reset), http.StatusNotFound, "user_not_found")
}

func TestSeal(t *testing.T) {
	e := openEnv(t)
	if rec := e.do(t, http.MethodPost, "/v1/seal", ""); rec.Code != http.StatusOK {
		t.Fatalf("seal: %d %s", rec.Code, rec.Body.String())
	}
	if !e.vault.Sealed() {
		t.Fatal("o cofre deveria estar selado")
	}
	wantError(t, e.do(t, http.MethodGet, secretPath, ""), http.StatusServiceUnavailable, "sealed")
	wantError(t, e.do(t, http.MethodPost, "/v1/seal", ""), http.StatusConflict, "already_sealed")
}
