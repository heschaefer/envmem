package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/heschaefer/envmem/internal/store"

	"github.com/heschaefer/envmem/internal/vault"
)

const secretPath = "/v1/projects/demo/secrets"

// openEnv devolve um ambiente de teste com o cofre já aberto e o projeto
// demo criado.
func openEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newTestEnv(t)
	e.key = vaultKey(t)
	if rec := e.unseal(t, e.key); rec.Code != http.StatusOK {
		t.Fatalf("unseal: %d", rec.Code)
	}
	e.createProject(t, "demo")
	return e
}

// vaultKey gera uma chave-mestra nova, em base64.
func vaultKey(t *testing.T) string {
	t.Helper()
	return vault.EncodeKey(vault.GenerateKey())
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

func TestSecretMetaAndSingleGet(t *testing.T) {
	e := openEnv(t)
	e.put(t, "demo", "DB_PASSWORD", "versao-um")
	e.put(t, "demo", "DB_PASSWORD", "versao-dois")

	rec := e.do(t, http.MethodGet, secretPath+"/meta", "")
	if strings.Contains(rec.Body.String(), "versao-") {
		t.Fatalf("meta expõe valores: %s", rec.Body.String())
	}
	meta := decode[secretsMetaResponse](t, rec).Secrets
	if len(meta) != 1 || meta[0].Key != "DB_PASSWORD" || meta[0].Version != 2 || meta[0].Versions != 2 {
		t.Fatalf("meta = %+v", meta)
	}

	if got := decode[secretResponse](t, e.do(t, http.MethodGet, secretPath+"/DB_PASSWORD", "")); got.Value != "versao-dois" || got.Version != 2 {
		t.Errorf("atual = %+v", got)
	}
	if got := decode[secretResponse](t, e.do(t, http.MethodGet, secretPath+"/DB_PASSWORD?version=1", "")); got.Value != "versao-um" {
		t.Errorf("versão 1 = %+v", got)
	}
	wantError(t, e.do(t, http.MethodGet, secretPath+"/DB_PASSWORD?version=9", ""), http.StatusNotFound, "secret_not_found")
	wantError(t, e.do(t, http.MethodGet, secretPath+"/DB_PASSWORD?version=abc", ""), http.StatusBadRequest, "invalid_version")
	wantError(t, e.do(t, http.MethodGet, secretPath+"/NAO_EXISTE", ""), http.StatusNotFound, "secret_not_found")

	// Selado: o valor não sai, mas os nomes sim (nada é decifrado).
	e.vault.Seal()
	wantError(t, e.do(t, http.MethodGet, secretPath+"/DB_PASSWORD", ""), http.StatusServiceUnavailable, "sealed")
	if rec := e.do(t, http.MethodGet, secretPath+"/meta", ""); rec.Code != http.StatusOK {
		t.Errorf("meta com o cofre selado: %d", rec.Code)
	}
}

func runValues(t *testing.T, e *testEnv) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, it := range decode[listSecretsResponse](t, e.do(t, http.MethodGet, secretPath, "")).Secrets {
		out[it.Key] = it.Value
	}
	return out
}

func TestTrash(t *testing.T) {
	e := openEnv(t)
	e.put(t, "demo", "DB_PASSWORD", "vazada")
	e.put(t, "demo", "API_KEY", "a")
	path := secretPath + "/DB_PASSWORD"

	// Remover manda para a lixeira: some do run e da listagem de nomes.
	if rec := e.do(t, http.MethodDelete, path, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("lixeira: %d %s", rec.Code, rec.Body.String())
	}
	if v := runValues(t, e); len(v) != 1 || v["API_KEY"] != "a" {
		t.Fatalf("run depois da lixeira = %v", v)
	}
	wantError(t, e.do(t, http.MethodDelete, path, ""), http.StatusNotFound, "secret_not_found")
	trash := decode[trashResponse](t, e.do(t, http.MethodGet, "/v1/projects/demo/trash", "")).Trash
	if len(trash) != 1 || trash[0].Key != "DB_PASSWORD" || trash[0].Version != 1 {
		t.Fatalf("lixeira = %+v", trash)
	}

	// Restaurar devolve o segredo.
	if rec := e.do(t, http.MethodPost, path+"/restore", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("restaurar: %d", rec.Code)
	}
	if v := runValues(t, e); v["DB_PASSWORD"] != "vazada" {
		t.Fatalf("depois de restaurar = %v", v)
	}
	wantError(t, e.do(t, http.MethodPost, path+"/restore", ""), http.StatusNotFound, "not_in_trash")

	// PUT numa chave da lixeira grava a versão seguinte e a tira de lá; o
	// valor antigo nunca volta ao run.
	e.do(t, http.MethodDelete, path, "")
	rec := e.put(t, "demo", "DB_PASSWORD", "nova")
	if got := decode[putSecretResponse](t, rec); got.Version != 2 {
		t.Fatalf("versão depois da lixeira = %d, quero 2", got.Version)
	}
	if v := runValues(t, e); v["DB_PASSWORD"] != "nova" {
		t.Fatalf("run depois do PUT = %v", v)
	}
	if trash := decode[trashResponse](t, e.do(t, http.MethodGet, "/v1/projects/demo/trash", "")).Trash; len(trash) != 0 {
		t.Fatalf("lixeira deveria estar vazia: %+v", trash)
	}
}

// Exclusão definitiva só do que está na lixeira; com a lixeira vazia, o
// projeto pode ser apagado (decisão 30).
func TestPurgeAndDeleteProject(t *testing.T) {
	e := openEnv(t)
	e.put(t, "demo", "DB_PASSWORD", "x")

	wantError(t, e.do(t, http.MethodDelete, "/v1/projects/demo/trash/DB_PASSWORD", ""), http.StatusNotFound, "not_in_trash")
	e.do(t, http.MethodDelete, secretPath+"/DB_PASSWORD", "")
	// Na lixeira, o segredo ainda está no banco: o projeto não pode sair.
	wantError(t, e.do(t, http.MethodDelete, "/v1/projects/demo", ""), http.StatusConflict, "project_not_empty")

	if rec := e.do(t, http.MethodDelete, "/v1/projects/demo/trash/DB_PASSWORD", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("exclusão definitiva: %d %s", rec.Code, rec.Body.String())
	}
	wantError(t, e.do(t, http.MethodPost, secretPath+"/DB_PASSWORD/restore", ""), http.StatusNotFound, "not_in_trash")
	if rec := e.do(t, http.MethodDelete, "/v1/projects/demo", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("apagar projeto vazio: %d", rec.Code)
	}
}

// Ficam só as 10 versões mais recentes (decisão 11).
func TestRetention(t *testing.T) {
	e := openEnv(t)
	for i := 1; i <= store.SecretRetention+2; i++ {
		e.put(t, "demo", "K", "v"+strconv.Itoa(i))
	}
	meta := decode[secretsMetaResponse](t, e.do(t, http.MethodGet, secretPath+"/meta", "")).Secrets
	if meta[0].Version != 12 || meta[0].Versions != store.SecretRetention {
		t.Fatalf("meta = %+v, quero versão 12 com 10 guardadas", meta[0])
	}
	wantError(t, e.do(t, http.MethodGet, secretPath+"/K?version=2", ""), http.StatusNotFound, "secret_not_found")
	if got := decode[secretResponse](t, e.do(t, http.MethodGet, secretPath+"/K?version=3", "")); got.Value != "v3" {
		t.Fatalf("versão 3 = %+v", got)
	}
}

func TestPutRejectsReservedNames(t *testing.T) {
	e := openEnv(t)
	wantError(t, e.put(t, "demo", "meta", "x"), http.StatusBadRequest, "invalid_key_name")
	wantError(t, e.put(t, "demo", "ENVMEM_TOKEN", "x"), http.StatusBadRequest, "invalid_key_name")
}
