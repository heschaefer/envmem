package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/heschaefer/envmem/internal/envname"
	"github.com/heschaefer/envmem/internal/store"
	"github.com/heschaefer/envmem/internal/vault"
)

type secretItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type listSecretsResponse struct {
	Project string       `json:"project"`
	Secrets []secretItem `json:"secrets"`
}

type putSecretRequest struct {
	Value string `json:"value"`
}

type putSecretResponse struct {
	Project string `json:"project"`
	Key     string `json:"key"`
	Version int    `json:"version"`
}

// handleListSecrets devolve a versão atual de cada segredo do projeto, com
// valor. É a rota usada pelo "envmem run".
func (s *server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	if s.vault.Sealed() {
		writeSealed(w)
		return
	}
	project, ok := s.lookupProject(w, r)
	if !ok {
		return
	}

	rows, err := s.store.LatestSecrets(r.Context(), project.ID)
	if err != nil {
		s.logger.Error("listar segredos", "project", project.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	items := make([]secretItem, 0, len(rows))
	for _, row := range rows {
		// O AAD usa o id do projeto: uma linha movida de outro projeto no
		// banco não decifra aqui.
		plaintext, err := s.vault.DecryptSecret(project.ID, row.Key, envelopeOf(row))
		if errors.Is(err, vault.ErrSealed) {
			writeSealed(w)
			return
		}
		if err != nil {
			// Não decifrar com o cofre aberto indica linha adulterada ou
			// movida de outro projeto (AAD). Falha a requisição inteira: um
			// ambiente pela metade esconderia o problema.
			s.logger.Error("segredo não decifra: possível adulteração no banco",
				"project", project.Name, "key", row.Key, "version", row.Version)
			writeError(w, http.StatusInternalServerError, "decrypt_failed", "não foi possível decifrar os segredos do projeto")
			return
		}
		items = append(items, secretItem{Key: row.Key, Value: string(plaintext)})
		clear(plaintext)
	}
	writeJSON(w, http.StatusOK, listSecretsResponse{Project: project.Name, Secrets: items})
}

// handlePutSecret grava uma nova versão do segredo, com o valor no corpo
// ({"value": "..."}). Nunca no caminho nem na query: iriam para logs.
func (s *server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	if err := envname.Check(key); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key_name", err.Error())
		return
	}
	if s.vault.Sealed() {
		writeSealed(w)
		return
	}

	var req putSecretRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", `corpo JSON inválido (esperado {"value": "..."})`)
		return
	}
	// O CLI recusaria o valor depois: o execve não aceita byte nulo.
	if strings.IndexByte(req.Value, 0) >= 0 {
		writeError(w, http.StatusBadRequest, "invalid_value", "o valor não pode conter byte nulo")
		return
	}
	// O projeto precisa existir: o PUT não cria projeto implicitamente, para
	// que um nome digitado errado não gere um projeto novo.
	project, ok := s.lookupProject(w, r)
	if !ok {
		return
	}

	value := []byte(req.Value)
	env, err := s.vault.EncryptSecret(project.ID, key, value)
	clear(value)
	if errors.Is(err, vault.ErrSealed) {
		writeSealed(w)
		return
	}
	if err != nil {
		s.logger.Error("cifrar segredo", "project", project.Name, "key", key, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	version, err := s.store.InsertSecretVersion(r.Context(), store.SecretRow{
		ProjectID:  project.ID,
		Key:        key,
		Ciphertext: env.Ciphertext,
		Nonce:      env.Nonce,
		WrappedDEK: env.WrappedDEK,
		DEKNonce:   env.DEKNonce,
	})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "conflict", "outra gravação deste segredo aconteceu ao mesmo tempo; tente de novo")
		return
	}
	if errors.Is(err, store.ErrNotFound) { // projeto apagado durante o PUT
		writeProjectNotFound(w)
		return
	}
	if err != nil {
		s.logger.Error("gravar segredo", "project", project.Name, "key", key, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	s.logger.Info("segredo gravado", "project", project.Name, "key", key, "version", version)
	writeJSON(w, http.StatusCreated, putSecretResponse{Project: project.Name, Key: key, Version: version})
}

func envelopeOf(row store.SecretRow) vault.Envelope {
	return vault.Envelope{
		Ciphertext: row.Ciphertext,
		Nonce:      row.Nonce,
		WrappedDEK: row.WrappedDEK,
		DEKNonce:   row.DEKNonce,
	}
}

func writeSealed(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "sealed", "o cofre está selado")
}
