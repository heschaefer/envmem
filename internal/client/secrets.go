package client

import (
	"context"
	"errors"
	"net/url"
)

// Secret é um segredo de projeto: o nome da variável de ambiente e o valor.
type Secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Secrets busca todos os segredos atuais do projeto, com valor
// (GET /v1/projects/{project}/secrets). É o que o "envmem run" injeta.
func (c *Client) Secrets(ctx context.Context, project string) ([]Secret, error) {
	if project == "" {
		return nil, errors.New("projeto não informado")
	}
	var resp struct {
		Secrets []Secret `json:"secrets"`
	}
	// PathEscape impede que um nome de projeto como "a/../b" mude a rota.
	path := "/v1/projects/" + url.PathEscape(project) + "/secrets"
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return resp.Secrets, nil
}
