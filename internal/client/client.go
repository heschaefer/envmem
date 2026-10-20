// Package client fala com o envmem-server pela API HTTP. É usado pelo CLI,
// tanto pelos subcomandos quanto (mais tarde) pelo modo interativo.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes limita o tamanho de uma resposta lida do servidor, para
// que um servidor defeituoso não esgote a memória do CLI.
const maxResponseBytes = 1 << 20 // 1 MiB

// Client é um cliente da API do envmem-server.
type Client struct {
	baseURL string
	http    *http.Client
}

// New cria um cliente para o servidor em baseURL (por exemplo,
// "http://localhost:8080").
func New(baseURL string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("endereço do servidor inválido: %q (exemplo: http://localhost:8080)", baseURL)
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// APIError é um erro devolvido pelo servidor no formato
// {"error": "codigo", "message": "texto"}.
type APIError struct {
	Status  int    // status HTTP
	Code    string // campo "error"; vazio se o corpo não estava no formato da API
	Message string // campo "message"
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("servidor respondeu %d %s", e.Status, http.StatusText(e.Status))
	}
	return fmt.Sprintf("servidor respondeu %d (%s): %s", e.Status, e.Code, e.Message)
}

// Health é o estado do servidor.
type Health struct {
	Status string `json:"status"`
	Sealed bool   `json:"sealed"`
}

// Health consulta GET /v1/health.
func (c *Client) Health(ctx context.Context) (Health, error) {
	var h Health
	err := c.getJSON(ctx, "/v1/health", &h)
	return h, err
}

// getJSON faz um GET em path e decodifica a resposta 200 em out. Qualquer
// outro status vira *APIError.
func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	return c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, out)
}

// doJSON envia uma requisição com in (se não for nil) como corpo JSON. Se o
// status for want, decodifica a resposta em out (se não for nil); qualquer
// outro status vira *APIError.
func (c *Client) doJSON(ctx context.Context, method, path string, in any, want int, out any) error {
	var reqBody io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("falha ao contatar o servidor: %w", err)
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, maxResponseBytes)

	if resp.StatusCode != want {
		return decodeAPIError(resp.StatusCode, body)
	}
	if out == nil {
		return nil
	}
	// O erro do decodificador é descartado de propósito: a mensagem dele
	// pode citar trechos do corpo, e o corpo pode conter segredos.
	if err := json.NewDecoder(body).Decode(out); err != nil {
		return errors.New("resposta inválida do servidor")
	}
	return nil
}

func decodeAPIError(status int, body io.Reader) error {
	apiErr := &APIError{Status: status}
	var eb struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	// Um corpo fora do formato da API (por exemplo, HTML de um proxy) não
	// impede o erro: fica só o status.
	if json.NewDecoder(body).Decode(&eb) == nil {
		apiErr.Code, apiErr.Message = eb.Error, eb.Message
	}
	return apiErr
}
