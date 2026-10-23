package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// User é uma conta do envmem, como o superadmin a vê. O hash da senha
// nunca sai do servidor.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	GlobalRole   string    `json:"global_role,omitempty"` // superadmin, admin ou vazio
	TempPassword bool      `json:"temp_password"`         // ainda não trocou a senha temporária
	CreatedAt    time.Time `json:"created_at"`
}

// Users lista os usuários (GET /v1/users, só superadmin).
func (c *Client) Users(ctx context.Context) ([]User, error) {
	var resp struct {
		Users []User `json:"users"`
	}
	if err := c.getJSON(ctx, "/v1/users", &resp); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// CreateUser cria um usuário com uma senha temporária, que ele troca no
// primeiro login (POST /v1/users, decisão 43). A senha vai no corpo.
func (c *Client) CreateUser(ctx context.Context, email, globalRole, tempPassword string) (User, error) {
	var u User
	in := struct {
		Email        string `json:"email"`
		GlobalRole   string `json:"global_role"`
		TempPassword string `json:"temp_password"`
	}{email, globalRole, tempPassword}
	err := c.doJSON(ctx, http.MethodPost, "/v1/users", in, http.StatusCreated, &u)
	return u, err
}

// DeleteUser remove um usuário (DELETE /v1/users/{id}). A rota recebe o
// id, nunca o e-mail: o caminho vai para o log do servidor.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	path, err := userPath(id, "")
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}

// ResetPassword define uma nova senha temporária para o usuário e revoga
// as sessões dele (POST /v1/users/{id}/password/reset, decisão 46).
func (c *Client) ResetPassword(ctx context.Context, id, tempPassword string) error {
	path, err := userPath(id, "/password/reset")
	if err != nil {
		return err
	}
	in := struct {
		TempPassword string `json:"temp_password"`
	}{tempPassword}
	return c.doJSON(ctx, http.MethodPost, path, in, http.StatusNoContent, nil)
}

func userPath(id, suffix string) (string, error) {
	if id == "" {
		return "", errors.New("usuário não informado")
	}
	return "/v1/users/" + url.PathEscape(id) + suffix, nil
}
