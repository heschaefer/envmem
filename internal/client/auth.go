package client

import (
	"context"
	"net/http"
	"time"
)

// LoginResult é a resposta de um login bem-sucedido.
type LoginResult struct {
	Token              string    `json:"token"`
	ExpiresAt          time.Time `json:"expires_at"`
	MustChangePassword bool      `json:"must_change_password"`
}

// Me descreve o dono da sessão.
type Me struct {
	Email              string `json:"email"`
	GlobalRole         string `json:"global_role"`
	MustChangePassword bool   `json:"must_change_password"`
}

// Login abre uma sessão (POST /v1/auth/login). A senha vai no corpo da
// requisição, dentro do TLS.
func (c *Client) Login(ctx context.Context, email, password string) (LoginResult, error) {
	var res LoginResult
	in := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{email, password}
	err := c.doJSON(ctx, http.MethodPost, "/v1/auth/login", in, http.StatusOK, &res)
	return res, err
}

// Logout revoga a sessão atual no servidor (POST /v1/auth/logout).
func (c *Client) Logout(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/auth/logout", nil, http.StatusNoContent, nil)
}

// Me consulta o dono da sessão (GET /v1/auth/me).
func (c *Client) Me(ctx context.Context) (Me, error) {
	var me Me
	err := c.getJSON(ctx, "/v1/auth/me", &me)
	return me, err
}

// ChangePassword troca a senha do próprio usuário (POST /v1/auth/password).
func (c *Client) ChangePassword(ctx context.Context, current, next string) error {
	in := struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}{current, next}
	return c.doJSON(ctx, http.MethodPost, "/v1/auth/password", in, http.StatusNoContent, nil)
}
