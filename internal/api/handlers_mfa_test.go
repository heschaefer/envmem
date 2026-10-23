package api

import (
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

// challenge faz o login de quem precisa de MFA e devolve o desafio.
func (e *testEnv) challenge(t *testing.T, email, wantMode string) string {
	t.Helper()
	rec := e.login(t, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", email, rec.Code, rec.Body.String())
	}
	got := decode[mfaChallengeResponse](t, rec)
	if got.MFA != wantMode || got.Challenge == "" || strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("login %s = %s, quero desafio %q e nenhuma sessão", email, rec.Body.String(), wantMode)
	}
	return got.Challenge
}

func (e *testEnv) mfaSetup(t *testing.T, challenge string) (secret []byte) {
	t.Helper()
	rec := e.doAs(t, "", http.MethodPost, "/v1/auth/mfa/setup", `{"challenge":"`+challenge+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	got := decode[mfaSetupResponse](t, rec)
	if !strings.HasPrefix(got.URI, "otpauth://totp/envmem:") || !strings.Contains(got.URI, "secret="+got.Secret) {
		t.Fatalf("setup = %+v", got)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(got.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func (e *testEnv) mfaVerify(t *testing.T, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()
	return e.doAs(t, "", http.MethodPost, "/v1/auth/mfa", `{"challenge":"`+challenge+`","code":"`+code+`"}`)
}

// enrollRoot cadastra o MFA do superadmin do ambiente e devolve o segredo.
// O relógio avança um passo, para o próximo código ser outro.
func (e *testEnv) enrollRoot(t *testing.T) []byte {
	t.Helper()
	ch := e.challenge(t, "root@empresa.com", "setup")
	secret := e.mfaSetup(t, ch)
	if rec := e.mfaVerify(t, ch, auth.TOTPCode(secret, e.clock.now())); rec.Code != http.StatusOK {
		t.Fatalf("confirmar cadastro: %d %s", rec.Code, rec.Body.String())
	}
	e.clock.add(30 * time.Second)
	return secret
}

// giveMFA grava, direto no store, um MFA já confirmado para o usuário
// (cifrado pelo cofre, que precisa estar aberto) e devolve o segredo. Para
// os testes que não são sobre o cadastro.
func (e *testEnv) giveMFA(t *testing.T, email string) []byte {
	t.Helper()
	u, err := e.store.UserByEmail(t.Context(), email)
	if err != nil {
		t.Fatal(err)
	}
	secret := auth.NewTOTPSecret()
	env, err := e.vault.EncryptTOTP(u.ID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.StartTOTP(t.Context(), store.TOTP{UserID: u.ID, Ciphertext: env.Ciphertext, Nonce: env.Nonce, WrappedDEK: env.WrappedDEK, DEKNonce: env.DEKNonce}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.ConfirmTOTP(t.Context(), u.ID, 0); err != nil {
		t.Fatal(err)
	}
	return secret
}

// wrongCode é um código de 6 dígitos diferente do certo agora.
func wrongCode(secret []byte, now time.Time) string {
	if auth.TOTPCode(secret, now) == "000000" {
		return "111111"
	}
	return "000000"
}

func TestMFAEnrollAndLogin(t *testing.T) {
	e := openEnv(t)
	e.store.audit = nil

	// Primeiro login do superadmin: senha certa, mas sem MFA ainda.
	ch := e.challenge(t, "root@empresa.com", "setup")
	// Sem cadastro, conferir código não faz sentido.
	wantError(t, e.mfaVerify(t, ch, "123456"), http.StatusConflict, "mfa_setup_required")
	// Recomeçar o cadastro gera outro segredo; vale o último.
	e.mfaSetup(t, ch)
	secret := e.mfaSetup(t, ch)

	// Código errado no cadastro: recusado, sem contar para a trava.
	wantError(t, e.mfaVerify(t, ch, wrongCode(secret, e.clock.now())), http.StatusUnauthorized, "invalid_mfa_code")
	code := auth.TOTPCode(secret, e.clock.now())
	rec := e.mfaVerify(t, ch, code)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmar: %d %s", rec.Code, rec.Body.String())
	}
	token := decode[loginResponse](t, rec).Token
	if rec := e.doAs(t, token, http.MethodGet, "/v1/auth/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("a sessão do MFA não vale: %d", rec.Code)
	}
	// O desafio é de uso único.
	wantError(t, e.mfaVerify(t, ch, code), http.StatusUnauthorized, "invalid_challenge")
	// Depois de confirmado, outro cadastro é recusado.
	ch = e.challenge(t, "root@empresa.com", "verify")
	wantError(t, e.doAs(t, "", http.MethodPost, "/v1/auth/mfa/setup", `{"challenge":"`+ch+`"}`), http.StatusConflict, "mfa_enrolled")

	// O mesmo código não vale duas vezes, nem no mesmo passo de 30 s.
	wantError(t, e.mfaVerify(t, ch, code), http.StatusUnauthorized, "invalid_mfa_code")
	e.clock.add(30 * time.Second)
	if rec := e.mfaVerify(t, ch, auth.TOTPCode(secret, e.clock.now())); rec.Code != http.StatusOK {
		t.Fatalf("login com o código seguinte: %d %s", rec.Code, rec.Body.String())
	}

	want := []string{
		"auth.mfa_challenge:success", "auth.mfa:failure", "mfa.enroll:success", "auth.login:success",
		"auth.mfa_challenge:success", "auth.mfa:failure", "auth.login:success",
	}
	if got := e.store.actions(); !slices.Equal(got, want) {
		t.Errorf("auditoria = %v, quero %v", got, want)
	}
	// O segredo nunca vai para o log.
	if enc := auth.EncodeTOTPSecret(secret); strings.Contains(e.logs.String(), enc) {
		t.Error("o segredo do TOTP apareceu no log")
	}
}

// Superadmin, admin e gestor precisam de MFA; o desenvolvedor, não.
func TestMFAWhoNeedsIt(t *testing.T) {
	e := openEnv(t)
	demo, _ := e.store.ProjectByName(t.Context(), "demo")
	dev := e.addUser(t, "dev@empresa.com", testPassword, 0)
	e.store.setMember(demo.ID, dev.ID, store.RoleDesenvolvedor)
	e.store.addUser(store.User{Email: "admin@empresa.com", GlobalRole: store.RoleAdmin, PasswordHash: rootHash()})

	if rec := e.login(t, "dev@empresa.com", testPassword); rec.Code != http.StatusOK || decode[loginResponse](t, rec).Token == "" {
		t.Fatalf("desenvolvedor: %d %s", rec.Code, rec.Body.String())
	}
	e.challenge(t, "admin@empresa.com", "setup")
	// Promovido a gestor, o mesmo usuário passa a precisar de MFA.
	e.store.setMember(demo.ID, dev.ID, store.RoleGestor)
	e.challenge(t, "dev@empresa.com", "setup")
}

// Com o cofre selado, o segredo do TOTP não decifra: quem tem MFA não entra.
func TestMFASealed(t *testing.T) {
	e := newTestEnv(t)
	wantError(t, e.login(t, "root@empresa.com", testPassword), http.StatusServiceUnavailable, "sealed")
	// Senha errada continua sendo 401: o 503 não confirma senhas.
	wantError(t, e.login(t, "root@empresa.com", "senha errada mas longa"), http.StatusUnauthorized, "invalid_credentials")
}

// O desafio vence em 5 minutos e aceita até 5 códigos errados.
func TestMFAChallengeLimits(t *testing.T) {
	e := openEnv(t)
	secret := e.enrollRoot(t)

	ch := e.challenge(t, "root@empresa.com", "verify")
	e.clock.add(auth.MFAChallengeTTL)
	wantError(t, e.mfaVerify(t, ch, auth.TOTPCode(secret, e.clock.now())), http.StatusUnauthorized, "invalid_challenge")

	ch = e.challenge(t, "root@empresa.com", "verify")
	for range auth.MFAChallengeMaxFailures {
		wantError(t, e.mfaVerify(t, ch, wrongCode(secret, e.clock.now())), http.StatusUnauthorized, "invalid_mfa_code")
	}
	wantError(t, e.mfaVerify(t, ch, auth.TOTPCode(secret, e.clock.now())), http.StatusUnauthorized, "invalid_challenge")
	// Com a senha de novo, outro desafio: o código certo entra (e zera as
	// falhas seguidas da conta).
	ch = e.challenge(t, "root@empresa.com", "verify")
	if rec := e.mfaVerify(t, ch, auth.TOTPCode(secret, e.clock.now())); rec.Code != http.StatusOK {
		t.Fatalf("código certo: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.store.TOTPByUser(t.Context(), "user-1"); got.Failures != 0 {
		t.Errorf("falhas depois do código certo = %d, quero 0", got.Failures)
	}
}

// 10 códigos errados seguidos travam o MFA da conta: nem a senha certa
// seguida do código certo entra, até o reset.
func TestMFALock(t *testing.T) {
	e := openEnv(t)
	secret := e.enrollRoot(t)
	e.store.audit = nil

	var rec *httptest.ResponseRecorder
	for i := 1; i <= auth.MFAMaxFailures; i++ {
		// Um desafio novo a cada 5 falhas; e o limite do login (10 falhas
		// a cada 5 minutos) é contornado avançando o relógio, como faria um
		// atacante paciente.
		ch := e.challenge(t, "root@empresa.com", "verify")
		rec = e.mfaVerify(t, ch, wrongCode(secret, e.clock.now()))
		e.clock.add(auth.LoginBlock)
	}
	wantError(t, rec, http.StatusForbidden, "mfa_locked")
	if !slices.Contains(e.store.actions(), "mfa.locked:success") {
		t.Errorf("a trava não foi para a auditoria: %v", e.store.actions())
	}
	wantError(t, e.login(t, "root@empresa.com", testPassword), http.StatusForbidden, "mfa_locked")
}

// O reset do MFA destrava a conta, revoga as sessões e faz o usuário
// cadastrar de novo; só um superadmin faz, e não para si mesmo.
func TestResetMFA(t *testing.T) {
	e := openEnv(t)
	secret := e.enrollRoot(t)
	// Um segundo superadmin, que faz o reset do primeiro.
	e.store.addUser(store.User{Email: "outro@empresa.com", GlobalRole: store.RoleSuperadmin, PasswordHash: rootHash()})
	other := e.sessionFor(t, "outro@empresa.com")
	root, _ := e.store.UserByEmail(t.Context(), "root@empresa.com")
	path := "/v1/users/" + root.ID + "/mfa/reset"

	// Trava o MFA do root com 10 códigos errados.
	for range auth.MFAMaxFailures {
		ch := e.challenge(t, "root@empresa.com", "verify")
		e.mfaVerify(t, ch, wrongCode(secret, e.clock.now()))
		e.clock.add(auth.LoginBlock)
	}
	wantError(t, e.login(t, "root@empresa.com", testPassword), http.StatusForbidden, "mfa_locked")
	rootToken := e.sessionFor(t, "root@empresa.com") // uma sessão aberta antes do reset

	// Ninguém reseta o próprio MFA; admin e desenvolvedor não resetam
	// nenhum (só o superadmin, decisão 36).
	wantError(t, e.doAs(t, rootToken, http.MethodPost, path, ""), http.StatusConflict, "cannot_reset_self")
	dev := e.addUser(t, "dev@empresa.com", testPassword, 0)
	devToken := e.tokenFor(t, "dev@empresa.com", testPassword)
	wantError(t, e.doAs(t, devToken, http.MethodPost, path, ""), http.StatusForbidden, "forbidden")
	e.store.addUser(store.User{Email: "admin@empresa.com", GlobalRole: store.RoleAdmin, PasswordHash: rootHash()})
	wantError(t, e.doAs(t, e.sessionFor(t, "admin@empresa.com"), http.MethodPost, path, ""), http.StatusForbidden, "forbidden")

	if rec := e.doAs(t, other, http.MethodPost, path, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	// As sessões do root caíram, e o próximo login pede um cadastro novo.
	if rec := e.doAs(t, rootToken, http.MethodGet, "/v1/auth/me", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("sessão depois do reset: %d, quero 401", rec.Code)
	}
	e.challenge(t, "root@empresa.com", "setup")
	if !slices.Contains(e.store.actions(), "mfa.reset:success") {
		t.Errorf("o reset não foi para a auditoria")
	}
	// Sem MFA (ou usuário inexistente): 404.
	wantError(t, e.doAs(t, other, http.MethodPost, "/v1/users/"+dev.ID+"/mfa/reset", ""), http.StatusNotFound, "mfa_not_found")
	wantError(t, e.doAs(t, other, http.MethodPost, "/v1/users/nao-existe/mfa/reset", ""), http.StatusNotFound, "mfa_not_found")
}

// A exclusão definitiva pede o código de novo, com as regras do login.
func TestPurgeRequiresMFACode(t *testing.T) {
	e := openEnv(t)
	secret := e.giveMFA(t, "root@empresa.com")
	e.put(t, "demo", "DB_PASSWORD", "x")
	e.do(t, http.MethodDelete, secretPath+"/DB_PASSWORD", "")
	purge := func(body string) *httptest.ResponseRecorder {
		return e.do(t, http.MethodDelete, "/v1/projects/demo/trash/DB_PASSWORD", body)
	}

	wantError(t, purge(""), http.StatusForbidden, "mfa_code_required")
	wantError(t, purge(`{"mfa_code":"`+wrongCode(secret, e.clock.now())+`"}`), http.StatusUnauthorized, "invalid_mfa_code")
	code := auth.TOTPCode(secret, e.clock.now())
	if rec := purge(`{"mfa_code":"` + code + `"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("exclusão com código: %d %s", rec.Code, rec.Body.String())
	}
	// O código vale uma vez: na próxima exclusão, só o do passo seguinte.
	e.put(t, "demo", "DB_PASSWORD", "y")
	e.do(t, http.MethodDelete, secretPath+"/DB_PASSWORD", "")
	wantError(t, purge(`{"mfa_code":"`+code+`"}`), http.StatusUnauthorized, "invalid_mfa_code")
	// Com o cofre selado, o segredo do TOTP não decifra.
	e.vault.Seal()
	wantError(t, purge(`{"mfa_code":"`+auth.TOTPCode(secret, e.clock.now().Add(30*time.Second))+`"}`), http.StatusServiceUnavailable, "sealed")
}
