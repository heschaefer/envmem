package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// Project é um projeto do envmem. Cada ambiente (app-prod, app-homo) é um
// projeto.
type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role,omitempty"` // papel de quem pediu: global (superadmin, admin) ou no projeto (gestor, desenvolvedor)
}

// Projects lista os projetos de quem está logado, com o papel em cada um
// (GET /v1/projects). Quem não é membro de um projeto nem o vê.
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	var resp struct {
		Projects []Project `json:"projects"`
	}
	if err := c.getJSON(ctx, "/v1/projects", &resp); err != nil {
		return nil, err
	}
	return resp.Projects, nil
}

// CreateProject cria um projeto (POST /v1/projects). Quem confere o formato
// do nome é o servidor.
func (c *Client) CreateProject(ctx context.Context, name string) (Project, error) {
	var p Project
	in := struct {
		Name string `json:"name"`
	}{name}
	err := c.doJSON(ctx, http.MethodPost, "/v1/projects", in, http.StatusCreated, &p)
	return p, err
}

// DeleteProject remove um projeto vazio (DELETE /v1/projects/{name}).
func (c *Client) DeleteProject(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("projeto não informado")
	}
	return c.doJSON(ctx, http.MethodDelete, "/v1/projects/"+url.PathEscape(name), nil, http.StatusNoContent, nil)
}
