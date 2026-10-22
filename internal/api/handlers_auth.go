package api

import (
	"bytes"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token              string    `json:"token"`
	ExpiresAt          time.Time `json:"expires_at"`
	MustChangePassword bool      `json:"must_change_password"`
}

type meResponse struct {
	Email              string `json:"email"`
	GlobalRole         string `json:"global_role,omitempty"`
	MustChangePassword bool   `json:"must_change_password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// handleLogin confere e-mail e senha e abre uma sessão. As respostas de
// falha não dizem se o e-mail existe: e-mail desconhecido e senha errada
// dão a mesma mensagem e levam o mesmo tempo.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `corpo JSON inválido (esperado {"email": "...", "password": "..."})`)
		return
	}
	password := []byte(req.Password)
	defer clear(password)

	// E-mail fora do formato segue o mesmo caminho de um e-mail
	// inexistente, inclusive no limite de tentativas por IP.
	email, emailErr := auth.NormalizeEmail(req.Email)
	keys := []string{"ip:" + clientIP(r)}
	if emailErr == nil {
		keys = append(keys, "email:"+email)
	}
	if wait := s.limiter.Wait(keys...); wait > 0 {
		s.recordLogin(r, email, emailErr, store.AuditDenied)
		writeTooManyAttempts(w, wait)
		return
	}

	user, ok, err := s.checkPassword(r, email, emailErr, password)
	if err != nil {
		s.logger.Error("login: ler usuário", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	if !ok {
		s.limiter.Failure(keys...)
		s.recordDenied(r, loginEvent(r, s, user, store.AuditFailure))
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "e-mail ou senha incorretos")
		return
	}
	// O login certo zera só o contador da conta. Zerar o do IP permitiria
	// a um atacante com uma conta própria intercalar logins válidos para
	// nunca atingir o limite por IP enquanto testa senhas de outras contas.
	s.limiter.Reset("email:" + email)

	if exp := user.TempPasswordExpiresAt; exp != nil && !s.now().Before(*exp) {
		// A senha estava certa, mas venceu (decisão 43). Dizer isso não
		// ajuda um atacante: quem acertou a senha já sabia que ela existia.
		s.recordDenied(r, loginEvent(r, s, user, store.AuditFailure))
		writeError(w, http.StatusUnauthorized, "temp_password_expired",
			"a senha temporária venceu; peça uma nova a um superadmin")
		return
	}

	token, hash := auth.NewToken()
	expiresAt := s.now().Add(auth.SessionTTL)
	// A sessão e o evento entram juntos: sem registro, não há sessão.
	err = s.store.InTx(r.Context(), func(tx Store) error {
		if err := tx.CreateSession(r.Context(), hash, user.ID, expiresAt); err != nil {
			return err
		}
		return auditErr(tx.InsertAudit(r.Context(), loginEvent(r, s, user, store.AuditSuccess)))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: registrar login", "err", err)
		writeAuditFailed(w)
		return
	}
	if err != nil {
		s.logger.Error("login: criar sessão", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info("login", "user_id", user.ID)
	writeJSON(w, http.StatusOK, loginResponse{
		Token:              token,
		ExpiresAt:          expiresAt.UTC(),
		MustChangePassword: user.TempPasswordExpiresAt != nil,
	})
}

// loginEvent é o evento de um login. Só identifica o usuário se o e-mail
// corresponder a um usuário existente: o texto digitado não é guardado
// (pode ser uma senha digitada no campo errado).
func loginEvent(r *http.Request, s *server, user store.User, result string) store.AuditEvent {
	e := s.event(r, "auth.login", result)
	e.UserID, e.UserEmail = user.ID, ""
	if user.ID != "" {
		e.UserEmail = user.Email
	}
	return e
}

// recordLogin registra uma tentativa bloqueada pelo limite, identificando
// o usuário só se o e-mail existir.
func (s *server) recordLogin(r *http.Request, email string, emailErr error, result string) {
	var user store.User
	if emailErr == nil {
		if u, err := s.store.UserByEmail(r.Context(), email); err == nil {
			user = u
		}
	}
	s.recordDenied(r, loginEvent(r, s, user, result))
}

// checkPassword busca o usuário e confere a senha. Para e-mail inválido ou
// inexistente, gasta o mesmo tempo conferindo um hash falso. O argon2id
// usa 19 MiB por conferência; o semáforo hashSlots limita quantas rodam ao
// mesmo tempo, para uma rajada de logins não esgotar a memória.
func (s *server) checkPassword(r *http.Request, email string, emailErr error, password []byte) (store.User, bool, error) {
	select {
	case s.hashSlots <- struct{}{}:
		defer func() { <-s.hashSlots }()
	case <-r.Context().Done():
		return store.User{}, false, r.Context().Err()
	}

	if emailErr != nil {
		return store.User{}, auth.VerifyDummy(password), nil
	}
	user, err := s.store.UserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, auth.VerifyDummy(password), nil
	}
	if err != nil {
		return store.User{}, false, err
	}
	ok, err := auth.VerifyPassword(user.PasswordHash, password)
	if err != nil {
		// Hash fora do formato no banco: registra, mas responde como senha
		// errada, sem detalhes para o cliente.
		s.logger.Error("login: hash de senha inválido no banco", "user_id", user.ID)
		return store.User{}, false, nil
	}
	return user, ok, nil
}

// handleLogout revoga a sessão atual.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if err := s.store.DeleteSession(r.Context(), sess.tokenHash); err != nil {
		s.logger.Error("logout", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	// Exceção à falha fechada (decisão 7): o logout tira acesso, então a
	// sessão é revogada mesmo que o registro falhe.
	if err := s.store.InsertAudit(r.Context(), s.event(r, "auth.logout", store.AuditSuccess)); err != nil {
		s.logger.Error("auditoria: registrar logout (a sessão foi revogada mesmo assim)", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleMe devolve quem é o dono da sessão.
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := sessionFrom(r.Context()).user
	writeJSON(w, http.StatusOK, meResponse{
		Email:              u.Email,
		GlobalRole:         u.GlobalRole,
		MustChangePassword: u.TempPasswordExpiresAt != nil,
	})
}

// handleChangePassword troca a senha do próprio usuário. Exige a senha
// atual: um token roubado sozinho não basta para tomar a conta trocando a
// senha. As outras sessões do usuário são revogadas.
func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	var req changePasswordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body",
			`corpo JSON inválido (esperado {"current_password": "...", "new_password": "..."})`)
		return
	}
	current, next := []byte(req.CurrentPassword), []byte(req.NewPassword)
	defer clear(current)
	defer clear(next)

	// A senha atual também conta no limite de tentativas: senão, com um
	// token roubado, esta rota serviria para adivinhar a senha.
	key := "email:" + sess.user.Email
	if wait := s.limiter.Wait(key); wait > 0 {
		writeTooManyAttempts(w, wait)
		return
	}
	ok, err := auth.VerifyPassword(sess.user.PasswordHash, current)
	if err != nil || !ok {
		s.limiter.Failure(key)
		s.recordDenied(r, s.event(r, "auth.password_change", store.AuditFailure))
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "senha atual incorreta")
		return
	}
	if err := auth.CheckPasswordPolicy(next); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	if bytes.Equal(current, next) {
		writeError(w, http.StatusBadRequest, "invalid_password", "a nova senha precisa ser diferente da atual")
		return
	}

	err = s.store.InTx(r.Context(), func(tx Store) error {
		if err := tx.ChangePassword(r.Context(), sess.user.ID, auth.HashPassword(next), sess.tokenHash); err != nil {
			return err
		}
		return auditErr(tx.InsertAudit(r.Context(), s.event(r, "auth.password_change", store.AuditSuccess)))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: registrar troca de senha", "err", err)
		writeAuditFailed(w)
		return
	}
	if err != nil {
		s.logger.Error("trocar senha", "user_id", sess.user.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info("senha trocada", "user_id", sess.user.ID)
	w.WriteHeader(http.StatusNoContent)
}

// writeTooManyAttempts responde 429 com Retry-After em segundos (decisão 45).
func writeTooManyAttempts(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	writeError(w, http.StatusTooManyRequests, "too_many_attempts",
		"muitas tentativas seguidas; espere antes de tentar de novo")
}
