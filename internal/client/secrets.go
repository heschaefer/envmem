package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Secret é um segredo de projeto: o nome da variável de ambiente e o valor.
type Secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Secrets busca todos os segredos atuais do projeto, com valor
// (GET /v1/projects/{project}/secrets). É o que o "envmem run" injeta.
func (c *Client) Secrets(ctx context.Context, project string) ([]Secret, error) {
	path, err := projectPath(project, "/secrets")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Secrets []Secret `json:"secrets"`
	}
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return resp.Secrets, nil
}

// SecretMeta descreve um segredo sem o valor.
type SecretMeta struct {
	Key       string    `json:"key"`
	Version   int       `json:"version"`  // versão atual
	Versions  int       `json:"versions"` // quantas versões estão guardadas (até 10, decisão 11)
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretsMeta lista os nomes e as versões dos segredos do projeto, sem os
// valores (GET /v1/projects/{project}/secrets/meta). Até o desenvolvedor
// pode listar.
func (c *Client) SecretsMeta(ctx context.Context, project string) ([]SecretMeta, error) {
	path, err := projectPath(project, "/secrets/meta")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Secrets []SecretMeta `json:"secrets"`
	}
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return resp.Secrets, nil
}

// SecretVersion é um segredo com valor, numa versão.
type SecretVersion struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// Secret lê o valor de um segredo (GET /v1/projects/{project}/secrets/{key}):
// a versão atual com version 0, ou a versão pedida.
func (c *Client) Secret(ctx context.Context, project, key string, version int) (SecretVersion, error) {
	var s SecretVersion
	path, err := secretPath(project, "/secrets/", key)
	if err != nil {
		return s, err
	}
	// Na query só vai o número da versão, nunca um valor.
	if version > 0 {
		path += "?version=" + strconv.Itoa(version)
	}
	err = c.getJSON(ctx, path, &s)
	return s, err
}

// PutSecret grava uma nova versão do segredo e devolve o número dela
// (PUT /v1/projects/{project}/secrets/{key}). O valor vai no corpo da
// requisição, nunca na URL, que aparece em logs.
func (c *Client) PutSecret(ctx context.Context, project, key, value string) (int, error) {
	path, err := secretPath(project, "/secrets/", key)
	if err != nil {
		return 0, err
	}
	in := struct {
		Value string `json:"value"`
	}{value}
	var resp struct {
		Version int `json:"version"`
	}
	err = c.doJSON(ctx, http.MethodPut, path, in, http.StatusCreated, &resp)
	return resp.Version, err
}

// TrashSecret manda o segredo para a lixeira
// (DELETE /v1/projects/{project}/secrets/{key}).
func (c *Client) TrashSecret(ctx context.Context, project, key string) error {
	path, err := secretPath(project, "/secrets/", key)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}

// RestoreSecret tira o segredo da lixeira
// (POST /v1/projects/{project}/secrets/{key}/restore).
func (c *Client) RestoreSecret(ctx context.Context, project, key string) error {
	path, err := secretPath(project, "/secrets/", key)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodPost, path+"/restore", nil, http.StatusNoContent, nil)
}

// PurgeSecret exclui definitivamente um segredo da lixeira
// (DELETE /v1/projects/{project}/trash/{key}).
func (c *Client) PurgeSecret(ctx context.Context, project, key string) error {
	path, err := secretPath(project, "/trash/", key)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}

// TrashedSecret é um segredo na lixeira.
type TrashedSecret struct {
	Key       string    `json:"key"`
	Version   int       `json:"version"`
	DeletedAt time.Time `json:"deleted_at"`
}

// Trash lista a lixeira do projeto (GET /v1/projects/{project}/trash).
func (c *Client) Trash(ctx context.Context, project string) ([]TrashedSecret, error) {
	path, err := projectPath(project, "/trash")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Trash []TrashedSecret `json:"trash"`
	}
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return resp.Trash, nil
}

// projectPath monta /v1/projects/{project}{suffix}. PathEscape impede que
// um nome de projeto como "a/../b" mude a rota.
func projectPath(project, suffix string) (string, error) {
	if project == "" {
		return "", errors.New("projeto não informado")
	}
	return "/v1/projects/" + url.PathEscape(project) + suffix, nil
}

// secretPath monta /v1/projects/{project}{sep}{key}, com o mesmo cuidado
// para o nome do segredo.
func secretPath(project, sep, key string) (string, error) {
	if key == "" {
		return "", errors.New("segredo não informado")
	}
	return projectPath(project, sep+url.PathEscape(key))
}
