package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// Member é um membro de projeto, com o papel nele (gestor ou
// desenvolvedor).
type Member struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

// Members lista os membros do projeto (GET /v1/projects/{project}/members).
func (c *Client) Members(ctx context.Context, project string) ([]Member, error) {
	path, err := projectPath(project, "/members")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Members []Member `json:"members"`
	}
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return resp.Members, nil
}

// SetMember adiciona um usuário ao projeto, ou troca o papel dele
// (POST /v1/projects/{project}/members). O e-mail vai no corpo.
func (c *Client) SetMember(ctx context.Context, project, email, role string) (Member, error) {
	var m Member
	path, err := projectPath(project, "/members")
	if err != nil {
		return m, err
	}
	in := struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}{email, role}
	err = c.doJSON(ctx, http.MethodPost, path, in, http.StatusOK, &m)
	return m, err
}

// RemoveMember tira um usuário do projeto
// (DELETE /v1/projects/{project}/members/{user}). A rota recebe o id, nunca
// o e-mail: o caminho vai para o log do servidor.
func (c *Client) RemoveMember(ctx context.Context, project, userID string) error {
	if userID == "" {
		return errors.New("usuário não informado")
	}
	path, err := projectPath(project, "/members/"+url.PathEscape(userID))
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}
