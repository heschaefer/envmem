package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
	"github.com/heschaefer/envmem/internal/vault"
)

// Login em duas etapas com MFA (decisão 36). Para quem precisa de MFA, o
// POST /auth/login com a senha certa não devolve a sessão, e sim um
// desafio: um token curto (auth.MFAChallengeTTL), de uso único, guardado só
// como hash, como o de sessão. Com o desafio:
//
//   - POST /auth/mfa/setup, se ainda não há MFA cadastrado: gera o segredo
//     do TOTP e o devolve (para o QR code), a única vez em que ele sai do
//     servidor;
//   - POST /auth/mfa, com o código do app: confere e, se certo, abre a
//     sessão (e, no primeiro código, confirma o cadastro).
//
// O segredo do TOTP é cifrado pelo cofre: com o cofre selado, quem tem MFA
// não entra (503). As duas rotas são públicas, como o login: o desafio é a
// credencial.

type mfaChallengeResponse struct {
	// MFA diz o que falta: "verify" (digitar o código) ou "setup"
	// (cadastrar o app primeiro).
	MFA       string    `json:"mfa"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"challenge_expires_at"`
}

type mfaSetupRequest struct {
	Challenge string `json:"challenge"`
}

type mfaSetupResponse struct {
	Secret string `json:"secret"` // em base32, para digitar no app
	URI    string `json:"uri"`    // otpauth://, para o QR code
}

type mfaVerifyRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

// beginMFA responde ao login certo de quem precisa de MFA com um desafio.
// O evento auth.mfa_challenge registra que a senha foi aceita: mesmo que o
// código nunca chegue, quem acertou a senha fica na auditoria.
func (s *server) beginMFA(w http.ResponseWriter, r *http.Request, user store.User) {
	if s.vault.Sealed() {
		s.recordDenied(r, loginEvent(r, s, user, store.AuditFailure))
		writeError(w, http.StatusServiceUnavailable, "sealed",
			"o cofre está selado: quem tem MFA só entra com o cofre aberto")
		return
	}
	mode := "setup"
	t, err := s.store.TOTPByUser(r.Context(), user.ID)
	switch {
	case err == nil && t.ConfirmedAt != nil:
		if t.Failures >= auth.MFAMaxFailures {
			s.recordDenied(r, mfaEvent(r, s, user, "auth.mfa", store.AuditDenied))
			writeMFALocked(w)
			return
		}
		mode = "verify"
	case err != nil && !errors.Is(err, store.ErrNotFound):
		s.logger.Error("login: ler MFA", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	token, hash := auth.NewToken()
	expiresAt := s.now().Add(auth.MFAChallengeTTL)
	err = s.store.InTx(r.Context(), func(tx Store) error {
		if err := tx.CreateMFAChallenge(r.Context(), hash, user.ID, expiresAt); err != nil {
			return err
		}
		return auditErr(tx.InsertAudit(r.Context(), mfaEvent(r, s, user, "auth.mfa_challenge", store.AuditSuccess)))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: registrar desafio do MFA", "err", err)
		writeAuditFailed(w)
		return
	}
	if err != nil {
		s.logger.Error("login: criar desafio do MFA", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	writeJSON(w, http.StatusOK, mfaChallengeResponse{MFA: mode, Challenge: token, ExpiresAt: expiresAt.UTC()})
}

// handleMFASetup gera o segredo do TOTP de quem ainda não tem MFA e o
// devolve, para o CLI mostrar o QR code. Pode ser chamado de novo enquanto
// o cadastro não for confirmado (cada chamada gera outro segredo); depois
// de confirmado, trocar de app exige o reset por um superadmin.
func (s *server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	var req mfaSetupRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `corpo JSON inválido (esperado {"challenge": "..."})`)
		return
	}
	user, _, ok := s.challengeUser(w, r, req.Challenge)
	if !ok {
		return
	}
	if s.vault.Sealed() {
		writeSealed(w)
		return
	}

	secret := auth.NewTOTPSecret()
	defer clear(secret)
	env, err := s.vault.EncryptTOTP(user.ID, secret)
	if errors.Is(err, vault.ErrSealed) {
		writeSealed(w)
		return
	}
	if err != nil {
		s.logger.Error("MFA: cifrar segredo", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	err = s.store.StartTOTP(r.Context(), store.TOTP{
		UserID: user.ID, Ciphertext: env.Ciphertext, Nonce: env.Nonce, WrappedDEK: env.WrappedDEK, DEKNonce: env.DEKNonce,
	})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "mfa_enrolled", "o MFA já está cadastrado; para trocar de app, peça o reset a um superadmin")
		return
	}
	if err != nil {
		s.logger.Error("MFA: gravar cadastro", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	writeJSON(w, http.StatusOK, mfaSetupResponse{Secret: auth.EncodeTOTPSecret(secret), URI: auth.TOTPURI(user.Email, secret)})
}

// handleMFAVerify confere o código do app e, se certo, abre a sessão. Um
// código errado conta em três lugares: no limite do login (por conta e por
// IP, decisão 45), no desafio (depois de auth.MFAChallengeMaxFailures, é
// preciso digitar a senha de novo) e, com o MFA já confirmado, na trava da
// conta (auth.MFAMaxFailures seguidos travam até o reset).
func (s *server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaVerifyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `corpo JSON inválido (esperado {"challenge": "...", "code": "..."})`)
		return
	}
	user, hash, ok := s.challengeUser(w, r, req.Challenge)
	if !ok {
		return
	}
	keys := []string{"ip:" + clientIP(r), "email:" + user.Email}
	if wait := s.limiter.Wait(keys...); wait > 0 {
		s.recordDenied(r, mfaEvent(r, s, user, "auth.mfa", store.AuditDenied))
		writeTooManyAttempts(w, wait)
		return
	}
	if s.vault.Sealed() {
		writeSealed(w)
		return
	}

	t, err := s.store.TOTPByUser(r.Context(), user.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusConflict, "mfa_setup_required", "cadastre o MFA primeiro (POST /v1/auth/mfa/setup)")
		return
	}
	if err != nil {
		s.logger.Error("MFA: ler cadastro", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	confirmed := t.ConfirmedAt != nil
	if confirmed && t.Failures >= auth.MFAMaxFailures {
		s.recordDenied(r, mfaEvent(r, s, user, "auth.mfa", store.AuditDenied))
		writeMFALocked(w)
		return
	}

	step, ok, handled := s.matchTOTP(w, user, t, req.Code)
	if handled {
		return
	}
	if !ok {
		s.mfaFailure(w, r, user, hash, confirmed, keys)
		return
	}

	s.limiter.Reset("email:" + user.Email)
	s.createSession(w, r, user, func(tx Store) error {
		if confirmed {
			if err := tx.UseTOTPStep(r.Context(), user.ID, step, auth.MFAMaxFailures); err != nil {
				return err
			}
		} else {
			// Primeiro código certo: o cadastro está confirmado.
			if err := tx.ConfirmTOTP(r.Context(), user.ID, step); err != nil {
				return err
			}
			if err := tx.InsertAudit(r.Context(), mfaEvent(r, s, user, "mfa.enroll", store.AuditSuccess)); err != nil {
				return auditErr(err)
			}
		}
		// Uso único: o desafio some junto com a abertura da sessão.
		return tx.DeleteMFAChallenge(r.Context(), hash)
	})
}

// matchTOTP decifra o segredo do TOTP e confere o código, devolvendo o
// passo aceito. handled indica que já respondeu (cofre selado ou segredo
// que não decifra), e o handler só retorna.
func (s *server) matchTOTP(w http.ResponseWriter, user store.User, t store.TOTP, code string) (step int64, ok, handled bool) {
	secret, err := s.vault.DecryptTOTP(user.ID, vault.Envelope{
		Ciphertext: t.Ciphertext, Nonce: t.Nonce, WrappedDEK: t.WrappedDEK, DEKNonce: t.DEKNonce,
	})
	if errors.Is(err, vault.ErrSealed) {
		writeSealed(w)
		return 0, false, true
	}
	if err != nil {
		// Com o cofre aberto, só não decifra uma linha adulterada ou
		// copiada de outro usuário (AAD).
		s.logger.Error("MFA: segredo não decifra: possível adulteração no banco", "user_id", user.ID)
		writeError(w, http.StatusInternalServerError, "decrypt_failed", "não foi possível conferir o código")
		return 0, false, true
	}
	step, ok = auth.VerifyTOTP(secret, code, s.now(), t.LastStep)
	clear(secret)
	return step, ok, false
}

// requireMFACode confere o código do MFA pedido de novo numa ação sensível
// (a exclusão definitiva, decisão 11), para quem já tem sessão: mesmo com
// um token roubado, a ação exige o app. Valem as regras do login: cada
// código uma vez, limite de tentativas e trava. Se não puder seguir, já
// respondeu e devolve falso.
func (s *server) requireMFACode(w http.ResponseWriter, r *http.Request, code string) bool {
	user := sessionFrom(r.Context()).user
	if code == "" {
		writeError(w, http.StatusForbidden, "mfa_code_required", "esta ação pede o código do app autenticador")
		return false
	}
	keys := []string{"ip:" + clientIP(r), "email:" + user.Email}
	if wait := s.limiter.Wait(keys...); wait > 0 {
		writeTooManyAttempts(w, wait)
		return false
	}
	t, err := s.store.TOTPByUser(r.Context(), user.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.ConfirmedAt == nil) {
		// Sessão aberta antes do MFA existir: o próximo login cadastra.
		writeError(w, http.StatusForbidden, "mfa_setup_required",
			"esta ação pede o código do MFA, que ainda não foi cadastrado; entre de novo com envmem login")
		return false
	}
	if err != nil {
		s.logger.Error("MFA: ler cadastro", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return false
	}
	if t.Failures >= auth.MFAMaxFailures {
		writeMFALocked(w)
		return false
	}
	step, ok, handled := s.matchTOTP(w, user, t, code)
	if handled {
		return false
	}
	if !ok {
		s.mfaFailure(w, r, user, nil, true, keys)
		return false
	}
	err = s.store.UseTOTPStep(r.Context(), user.ID, step, auth.MFAMaxFailures)
	if errors.Is(err, store.ErrConflict) {
		writeInvalidMFACode(w) // o mesmo código, usado ao mesmo tempo em outra requisição
		return false
	}
	if err != nil {
		s.logger.Error("MFA: usar código", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return false
	}
	return true
}

// mfaFailure conta um código errado e responde. Se a conta chegou ao
// limite, o MFA trava agora, e o evento mfa.locked fica na auditoria.
func (s *server) mfaFailure(w http.ResponseWriter, r *http.Request, user store.User, hash []byte, confirmed bool, keys []string) {
	ctx := r.Context()
	s.limiter.Failure(keys...)
	// Sem desafio (hash nil): código pedido de novo numa ação, com sessão.
	if hash != nil {
		if n, err := s.store.FailMFAChallenge(ctx, hash); err == nil && n >= auth.MFAChallengeMaxFailures {
			if err := s.store.DeleteMFAChallenge(ctx, hash); err != nil {
				s.logger.Error("MFA: descartar desafio", "err", err)
			}
		}
	}
	locked := false
	if confirmed {
		n, err := s.store.FailTOTP(ctx, user.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Error("MFA: contar falha", "err", err)
		}
		locked = err == nil && n >= auth.MFAMaxFailures
	}
	s.recordDenied(r, mfaEvent(r, s, user, "auth.mfa", store.AuditFailure))
	if locked {
		s.recordDenied(r, mfaEvent(r, s, user, "mfa.locked", store.AuditSuccess))
		writeMFALocked(w)
		return
	}
	writeInvalidMFACode(w)
}

// challengeUser resolve o desafio do corpo no usuário dono dele. Desafio
// inexistente, vencido ou já usado responde 401 e devolve ok falso.
func (s *server) challengeUser(w http.ResponseWriter, r *http.Request, challenge string) (store.User, []byte, bool) {
	hash := auth.HashToken(challenge)
	userID, _, err := s.store.MFAChallenge(r.Context(), hash)
	if err == nil {
		var user store.User
		if user, err = s.store.UserByID(r.Context(), userID); err == nil {
			return user, hash, true
		}
	}
	if !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("MFA: ler desafio", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return store.User{}, nil, false
	}
	writeError(w, http.StatusUnauthorized, "invalid_challenge",
		"o desafio venceu, já foi usado ou é inválido; entre de novo com a senha")
	return store.User{}, nil, false
}

// mfaEvent é um evento do MFA, de quem está entrando (ainda sem sessão).
func mfaEvent(r *http.Request, s *server, user store.User, action, result string) store.AuditEvent {
	e := s.event(r, action, result)
	e.UserID, e.UserEmail = user.ID, user.Email
	return e
}

func writeInvalidMFACode(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "invalid_mfa_code", "código incorreto")
}

func writeMFALocked(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "mfa_locked",
		"o MFA desta conta travou por excesso de códigos errados; peça o reset a um superadmin")
}

// handleResetMFA apaga o MFA de um usuário (superadmin): quem perdeu o app
// autenticador, ou teve o MFA travado, cadastra de novo no próximo login.
// As sessões do usuário são revogadas, como no reset de senha. Não há
// códigos de recuperação: este é o caminho. Um superadmin não reseta o
// próprio MFA (precisa de outro; sendo o único, envmem-server reset-mfa).
func (s *server) handleResetMFA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user")
	if id == sessionFrom(r.Context()).user.ID {
		writeError(w, http.StatusConflict, "cannot_reset_self",
			"um superadmin não reseta o próprio MFA; peça a outro (sendo o único, use envmem-server reset-mfa no servidor)")
		return
	}
	err := s.store.InTx(r.Context(), func(tx Store) error {
		target, err := tx.UserByID(r.Context(), id)
		if err != nil {
			return err
		}
		if err := tx.ResetMFA(r.Context(), target.ID); err != nil {
			return err
		}
		e := s.event(r, "mfa.reset", store.AuditSuccess)
		e.TargetUserID, e.TargetEmail = target.ID, target.Email
		return auditErr(tx.InsertAudit(r.Context(), e))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: registrar reset de MFA", "err", err)
		writeAuditFailed(w)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "mfa_not_found", "usuário não encontrado, ou sem MFA cadastrado")
		return
	}
	if err != nil {
		s.logger.Error("resetar MFA", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info("MFA resetado", "user_id", id)
	w.WriteHeader(http.StatusNoContent)
}
