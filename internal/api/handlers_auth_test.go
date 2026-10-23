package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

const testPassword = "senha de teste bem longa"

// addUser cria um usuário com a senha dada. tempFor > 0 cria uma senha
// temporária que vence nesse prazo.
func (e *testEnv) addUser(t *testing.T, email, password string, tempFor time.Duration) store.User {
	t.Helper()
	u := store.User{Email: email, PasswordHash: auth.HashPassword([]byte(password))}
	if tempFor > 0 {
		exp := e.clock.now().Add(tempFor)
		u.TempPasswordExpiresAt = &exp
	}
	return e.store.addUser(u)
}

func (e *testEnv) login(t *testing.T, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodPost, "/v1/auth/login", `{"email":"`+email+`","password":"`+password+`"}`)
}

// tokenFor faz login e devolve o token, falhando o teste se não conseguir.
func (e *testEnv) tokenFor(t *testing.T, email, password string) string {
	t.Helper()
	rec := e.login(t, email, password)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", email, rec.Code, rec.Body.String())
	}
	return decode[loginResponse](t, rec).Token
}

// sessionFor abre uma sessão direto no store para o usuário, sem passar
// pelo login. Serve aos testes que não são sobre o login, para usuários que
// precisam de MFA (superadmin, admin, gestor): o fluxo do login com MFA tem
// testes próprios (handlers_mfa_test.go).
func (e *testEnv) sessionFor(t *testing.T, email string) string {
	t.Helper()
	u, err := e.store.UserByEmail(t.Context(), email)
	if err != nil {
		t.Fatalf("sessionFor %s: %v", email, err)
	}
	token, hash := auth.NewToken()
	if err := e.store.CreateSession(t.Context(), hash, u.ID, e.clock.now().Add(auth.SessionTTL)); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestLoginAndMe(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "dev@empresa.com", testPassword, 0)

	// O e-mail é normalizado: maiúsculas e espaços não atrapalham.
	rec := e.login(t, " Dev@Empresa.com", testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	got := decode[loginResponse](t, rec)
	if len(got.Token) != 43 || got.MustChangePassword {
		t.Fatalf("resposta = %+v", got)
	}
	if want := e.clock.now().Add(auth.SessionTTL); !got.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %v, quero %v (8 horas)", got.ExpiresAt, want)
	}

	me := decode[meResponse](t, e.doAs(t, got.Token, http.MethodGet, "/v1/auth/me", ""))
	if me.Email != "dev@empresa.com" {
		t.Errorf("me = %+v", me)
	}
}

func TestRequireAuth(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "dev@empresa.com", testPassword, 0)
	token := e.tokenFor(t, "dev@empresa.com", testPassword)

	for name, tok := range map[string]string{
		"sem token":        "",
		"token inventado":  strings.Repeat("A", 43),
		"formato estranho": "abc",
	} {
		t.Run(name, func(t *testing.T) {
			rec := e.doAs(t, tok, http.MethodGet, "/v1/auth/me", "")
			wantError(t, rec, http.StatusUnauthorized, "unauthorized")
			if rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("falta o cabeçalho WWW-Authenticate")
			}
		})
	}

	// O token na URL não é aceito: só no cabeçalho.
	wantError(t, e.doAs(t, "", http.MethodGet, "/v1/auth/me?token="+token, ""), http.StatusUnauthorized, "unauthorized")

	// A sessão vale 8 horas, contadas do login.
	e.clock.add(auth.SessionTTL - time.Second)
	if rec := e.doAs(t, token, http.MethodGet, "/v1/auth/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("antes de vencer: %d", rec.Code)
	}
	e.clock.add(time.Second)
	wantError(t, e.doAs(t, token, http.MethodGet, "/v1/auth/me", ""), http.StatusUnauthorized, "unauthorized")
}

// E-mail inexistente, senha errada e e-mail fora do formato dão a mesma
// resposta: o login não revela quais e-mails estão cadastrados.
func TestLoginFailuresLookAlike(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "dev@empresa.com", testPassword, 0)

	var bodies []string
	for _, rec := range []*httptest.ResponseRecorder{
		e.login(t, "dev@empresa.com", "senha errada mas longa"),
		e.login(t, "ninguem@empresa.com", testPassword),
		e.login(t, "não é e-mail", testPassword),
	} {
		wantError(t, rec, http.StatusUnauthorized, "invalid_credentials")
		bodies = append(bodies, rec.Body.String())
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("respostas diferentes: %q", bodies)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "vitima@empresa.com", testPassword, 0)
	e.addUser(t, "outra@empresa.com", testPassword, 0)

	for range auth.LoginMaxFailures {
		e.login(t, "vitima@empresa.com", "senha errada mas longa")
	}
	// Bloqueada por 5 minutos, mesmo com a senha certa.
	rec := e.login(t, "vitima@empresa.com", testPassword)
	wantError(t, rec, http.StatusTooManyRequests, "too_many_attempts")
	if got := rec.Header().Get("Retry-After"); got != strconv.Itoa(int(auth.LoginBlock.Seconds())) {
		t.Errorf("Retry-After = %q, quero 300", got)
	}
	// O mesmo IP também está bloqueado, para qualquer conta.
	wantError(t, e.login(t, "outra@empresa.com", testPassword), http.StatusTooManyRequests, "too_many_attempts")

	// Depois de 5 minutos, a senha certa entra. A conta não fica bloqueada.
	e.clock.add(auth.LoginBlock)
	if rec := e.login(t, "vitima@empresa.com", testPassword); rec.Code != http.StatusOK {
		t.Fatalf("depois da espera: %d %s", rec.Code, rec.Body.String())
	}
}

// Um login certo zera só o contador da conta, não o do IP: senão, um
// atacante com conta própria intercalaria logins válidos para nunca
// atingir o limite por IP enquanto testa senhas de outras contas.
func TestLoginSuccessDoesNotResetIPCounter(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "atacante@empresa.com", testPassword, 0)
	e.addUser(t, "vitima@empresa.com", testPassword, 0)

	for i := range auth.LoginMaxFailures {
		e.login(t, "vitima@empresa.com", "chute numero "+strconv.Itoa(i)+" longo")
		if i < auth.LoginMaxFailures-1 {
			e.tokenFor(t, "atacante@empresa.com", testPassword)
		}
	}
	wantError(t, e.login(t, "atacante@empresa.com", testPassword), http.StatusTooManyRequests, "too_many_attempts")
}

func TestLogout(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "dev@empresa.com", testPassword, 0)
	token := e.tokenFor(t, "dev@empresa.com", testPassword)
	other := e.tokenFor(t, "dev@empresa.com", testPassword)

	if rec := e.doAs(t, token, http.MethodPost, "/v1/auth/logout", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	// O token revogado não vale mais, na hora; a outra sessão continua.
	wantError(t, e.doAs(t, token, http.MethodGet, "/v1/auth/me", ""), http.StatusUnauthorized, "unauthorized")
	if rec := e.doAs(t, other, http.MethodGet, "/v1/auth/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("a outra sessão deveria continuar: %d", rec.Code)
	}
}

func TestTempPassword(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "novo@empresa.com", testPassword, 72*time.Hour)

	rec := e.login(t, "novo@empresa.com", testPassword)
	if rec.Code != http.StatusOK || !decode[loginResponse](t, rec).MustChangePassword {
		t.Fatalf("login com senha temporária: %d %s", rec.Code, rec.Body.String())
	}

	// Depois de 72 horas, a senha temporária não entra mais. Com a senha
	// errada, a resposta continua a de sempre: nada é revelado.
	e.clock.add(72 * time.Hour)
	wantError(t, e.login(t, "novo@empresa.com", testPassword), http.StatusUnauthorized, "temp_password_expired")
	wantError(t, e.login(t, "novo@empresa.com", "senha errada mas longa"), http.StatusUnauthorized, "invalid_credentials")
}

func TestChangePassword(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "novo@empresa.com", testPassword, 72*time.Hour)
	token := e.tokenFor(t, "novo@empresa.com", testPassword)
	other := e.tokenFor(t, "novo@empresa.com", testPassword)

	change := func(current, next string) *httptest.ResponseRecorder {
		return e.doAs(t, token, http.MethodPost, "/v1/auth/password",
			`{"current_password":"`+current+`","new_password":"`+next+`"}`)
	}
	wantError(t, change("senha errada mas longa", "nova senha bem longa"), http.StatusUnauthorized, "invalid_credentials")
	wantError(t, change(testPassword, "curta"), http.StatusBadRequest, "invalid_password")
	wantError(t, change(testPassword, testPassword), http.StatusBadRequest, "invalid_password")

	if rec := change(testPassword, "nova senha bem longa"); rec.Code != http.StatusNoContent {
		t.Fatalf("troca: %d %s", rec.Code, rec.Body.String())
	}
	// A sessão atual continua e deixa de ser temporária; as outras caem.
	me := decode[meResponse](t, e.doAs(t, token, http.MethodGet, "/v1/auth/me", ""))
	if me.MustChangePassword {
		t.Error("depois da troca, a senha não deveria ser temporária")
	}
	wantError(t, e.doAs(t, other, http.MethodGet, "/v1/auth/me", ""), http.StatusUnauthorized, "unauthorized")

	wantError(t, e.login(t, "novo@empresa.com", testPassword), http.StatusUnauthorized, "invalid_credentials")
	if rec := e.login(t, "novo@empresa.com", "nova senha bem longa"); rec.Code != http.StatusOK {
		t.Fatalf("login com a senha nova: %d", rec.Code)
	}
}

// Nem a senha nem o token aparecem no log.
func TestAuthLogsDoNotLeak(t *testing.T) {
	e := newTestEnv(t)
	e.addUser(t, "dev@empresa.com", testPassword, 0)
	token := e.tokenFor(t, "dev@empresa.com", testPassword)
	e.login(t, "dev@empresa.com", "senha errada mas longa")
	e.doAs(t, token, http.MethodGet, "/v1/auth/me", "")

	for _, s := range []string{testPassword, "senha errada mas longa", token} {
		if strings.Contains(e.logs.String(), s) {
			t.Fatalf("o log contém %q", s)
		}
	}
}

// Fora a lista de rotas públicas, tudo exige sessão.
func TestPrivateRoutesRequireSession(t *testing.T) {
	e := openEnv(t)
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/v1/projects"},
		{http.MethodPost, "/v1/projects"},
		{http.MethodDelete, "/v1/projects/demo"},
		{http.MethodGet, "/v1/projects/demo/secrets"},
		{http.MethodPut, "/v1/projects/demo/secrets/K"},
		{http.MethodPost, "/v1/auth/logout"},
		{http.MethodGet, "/v1/auth/me"},
		{http.MethodPost, "/v1/auth/password"},
	} {
		wantError(t, e.doAs(t, "", r.method, r.path, `{}`), http.StatusUnauthorized, "unauthorized")
	}
	for _, path := range []string{"/v1/health"} {
		if rec := e.doAs(t, "", http.MethodGet, path, ""); rec.Code != http.StatusOK {
			t.Errorf("%s sem token: %d, quero 200 (rota pública)", path, rec.Code)
		}
	}
}

// Com senha temporária, a sessão só troca a senha, consulta o me e sai.
func TestTempPasswordSessionIsRestricted(t *testing.T) {
	e := openEnv(t)
	e.addUser(t, "novo@empresa.com", testPassword, 72*time.Hour)
	token := e.tokenFor(t, "novo@empresa.com", testPassword)

	wantError(t, e.doAs(t, token, http.MethodGet, "/v1/projects", ""), http.StatusForbidden, "password_change_required")
	wantError(t, e.doAs(t, token, http.MethodGet, secretPath, ""), http.StatusForbidden, "password_change_required")
	if rec := e.doAs(t, token, http.MethodGet, "/v1/auth/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("me com senha temporária: %d", rec.Code)
	}

	e.doAs(t, token, http.MethodPost, "/v1/auth/password",
		`{"current_password":"`+testPassword+`","new_password":"nova senha bem longa"}`)
	if rec := e.doAs(t, token, http.MethodGet, "/v1/projects", ""); rec.Code != http.StatusOK {
		t.Fatalf("depois da troca: %d %s", rec.Code, rec.Body.String())
	}
}
