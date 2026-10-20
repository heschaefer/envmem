package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heschaefer/envmem/internal/vault"
)

const secretPath = "/v1/projects/demo/secrets"

// openEnv devolve um ambiente de teste com o cofre já aberto e o projeto
// demo criado.
func openEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newTestEnv(t)
	if rec := e.unseal(t, vault.EncodeKey(vault.GenerateKey())); rec.Code != http.StatusOK {
		t.Fatalf("unseal: %d", rec.Code)
	}
	e.createProject(t, "demo")
	return e
}

func (e *testEnv) put(t *testing.T, project, key, value string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodPut, "/v1/projects/"+project+"/secrets/"+key, `{"value":"`+value+`"}`)
}

func TestSealedReturns503(t *testing.T) {
	e := newTestEnv(t)
	e.createProject(t, "demo")
	wantError(t, e.do(t, http.MethodGet, secretPath, ""), http.StatusServiceUnavailable, "sealed")
	wantError(t, e.put(t, "demo", "DB_PASSWORD", "x"), http.StatusServiceUnavailable, "sealed")
}

func TestPutThenListLatestVersion(t *testing.T) {
	e := openEnv(t)

	for i, v := range []string{"senha-1", "senha-2"} {
		rec := e.put(t, "demo", "DB_PASSWORD", v)
		if rec.Code != http.StatusCreated {
			t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
		}
		if got := decode[putSecretResponse](t, rec); got.Version != i+1 {
			t.Errorf("versão = %d, quero %d", got.Version, i+1)
		}
	}
	e.put(t, "demo", "API_KEY", "chave")

	rec := e.do(t, http.MethodGet, secretPath, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, quero no-store", got)
	}
	body := decode[listSecretsResponse](t, rec)
	want := []secretItem{{Key: "API_KEY", Value: "chave"}, {Key: "DB_PASSWORD", Value: "senha-2"}}
	if len(body.Secrets) != 2 || body.Secrets[0] != want[0] || body.Secrets[1] != want[1] {
		t.Errorf("segredos = %+v, quero %+v", body.Secrets, want)
	}
}

// O store só recebe material cifrado.
func TestStoreNeverSeesPlaintext(t *testing.T) {
	e := openEnv(t)
	e.put(t, "demo", "DB_PASSWORD", "valor-em-claro")

	for _, row := range e.store.secrets {
		for _, b := range [][]byte{row.Ciphertext, row.Nonce, row.WrappedDEK, row.DEKNonce} {
			if bytes.Contains(b, []byte("valor-em-claro")) {
				t.Fatal("o store recebeu o valor em claro")
			}
		}
	}
}

func TestUnknownProject(t *testing.T) {
	e := openEnv(t)
	wantError(t, e.do(t, http.MethodGet, "/v1/projects/nao-existe/secrets", ""), http.StatusNotFound, "project_not_found")
	// O PUT não cria o projeto: um nome digitado errado não vira projeto novo.
	wantError(t, e.put(t, "nao-existe", "K", "x"), http.StatusNotFound, "project_not_found")
	if len(e.store.projects) != 1 {
		t.Fatal("o PUT não deveria ter criado projeto")
	}
}

// Desde a Fatia 3, projeto existente sem segredos responde 200 com lista
// vazia (antes, sem tabela de projetos, respondia 404).
func TestListEmptyProject(t *testing.T) {
	e := openEnv(t)
	rec := e.do(t, http.MethodGet, secretPath, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if body := decode[listSecretsResponse](t, rec); body.Secrets == nil || len(body.Secrets) != 0 {
		t.Fatalf("segredos = %#v, quero lista vazia (não null)", body.Secrets)
	}
}

func TestPutRejects(t *testing.T) {
	e := openEnv(t)
	wantError(t, e.put(t, "demo", "LD_PRELOAD", "/tmp/x.so"), http.StatusBadRequest, "invalid_key_name")
	wantError(t, e.put(t, "demo", "A-B", "x"), http.StatusBadRequest, "invalid_key_name")
	wantError(t, e.put(t, "demo", "OK", `\u0000`), http.StatusBadRequest, "invalid_value")
	wantError(t, e.do(t, http.MethodPut, secretPath+"/OK", `{"valor":"x"}`), http.StatusBadRequest, "invalid_body")
	if len(e.store.secrets) != 0 {
		t.Fatal("nada deveria ter sido gravado")
	}
}

// Uma linha movida para outro projeto pelo banco não decifra (AAD): a
// requisição falha inteira, e o log cita a chave, mas não o valor.
func TestMovedRowFailsClosed(t *testing.T) {
	e := openEnv(t)
	e.createProject(t, "app-prod")
	dev := e.createProject(t, "dev")
	e.put(t, "app-prod", "DB_PASSWORD", "senha-de-producao")
	e.put(t, "dev", "OUTRA", "x")

	// "Ataque" direto no banco: copia a linha de produção para o projeto dev.
	moved := e.store.secrets[0]
	moved.ProjectID = dev.ID
	e.store.secrets = append(e.store.secrets, moved)

	rec := e.do(t, http.MethodGet, "/v1/projects/dev/secrets", "")
	wantError(t, rec, http.StatusInternalServerError, "decrypt_failed")
	if strings.Contains(rec.Body.String(), "senha-de-producao") {
		t.Fatal("resposta contém o segredo de produção")
	}
	if !strings.Contains(e.logs.String(), "DB_PASSWORD") {
		t.Error("o log deveria citar a chave que falhou")
	}
}

// Nem o PUT nem o GET deixam o valor no log.
func TestLogsDoNotContainSecretValues(t *testing.T) {
	e := openEnv(t)
	e.put(t, "demo", "DB_PASSWORD", "valor-que-nao-pode-vazar")
	e.do(t, http.MethodGet, secretPath, "")

	if strings.Contains(e.logs.String(), "valor-que-nao-pode-vazar") {
		t.Fatal("log contém o valor do segredo")
	}
}
