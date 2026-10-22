package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/heschaefer/envmem/internal/auth"
	"github.com/heschaefer/envmem/internal/store"
)

// session é quem fez a requisição: o usuário e o hash do token usado (para
// o logout e a troca de senha saberem qual sessão é a atual).
type session struct {
	user      store.User
	tokenHash []byte
}

type sessionKey struct{}

// sessionFrom devolve a sessão gravada no contexto por requireAuth.
func sessionFrom(ctx context.Context) session {
	s, _ := ctx.Value(sessionKey{}).(session)
	return s
}

// allowedWithTempPassword são as únicas rotas liberadas para quem entrou
// com senha temporária (decisão 43): até trocar a senha, a sessão não faz
// mais nada.
var allowedWithTempPassword = map[string]bool{
	"POST /v1/auth/password": true,
	"GET /v1/auth/me":        true,
	"POST /v1/auth/logout":   true,
}

// requireAuth exige um token de sessão válido no cabeçalho
// "Authorization: Bearer <token>". O token nunca vai na URL: iria para
// logs e para o histórico.
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := auth.HashToken(bearerToken(r))
		if hash == nil {
			writeUnauthorized(w)
			return
		}
		user, err := s.store.UserBySession(r.Context(), hash)
		if errors.Is(err, store.ErrNotFound) {
			// Token inexistente, vencido ou revogado: a mesma resposta para
			// os três, sem dizer qual foi.
			writeUnauthorized(w)
			return
		}
		if err != nil {
			s.logger.Error("ler sessão", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "erro interno")
			return
		}
		if user.TempPasswordExpiresAt != nil && !allowedWithTempPassword[r.Pattern] {
			writeError(w, http.StatusForbidden, "password_change_required",
				"troque a senha temporária antes de continuar")
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, session{user: user, tokenHash: hash})
		next(w, r.WithContext(ctx))
	}
}

// bearerToken extrai o token do cabeçalho Authorization, ou "" se não houver.
func bearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="envmem"`)
	writeError(w, http.StatusUnauthorized, "unauthorized", "sessão ausente, inválida ou vencida; faça login")
}

// clientIP é o IP de quem abriu a conexão. Cabeçalhos como
// X-Forwarded-For são ignorados de propósito: qualquer cliente pode
// inventá-los e, com eles, escapar do limite de tentativas por IP. Atrás
// de um proxy, todos os clientes aparecem com o IP do proxy.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
