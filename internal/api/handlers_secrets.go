package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	project := projectFrom(r.Context()).project

	rows, err := s.store.LatestSecrets(r.Context(), project.ID)
	if err != nil {
		s.logger.Error("listar segredos", "project", project.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	items := make([]secretItem, 0, len(rows))
	events := make([]store.AuditEvent, 0, len(rows))
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
		e := s.event(r, "secret.run", store.AuditSuccess)
		e.SecretKey, e.SecretVersion = row.Key, row.Version
		events = append(events, e)
	}
	// Uma linha por segredo entregue, com a versão (decisão 7). Os eventos
	// são gravados antes da resposta: se a gravação falhar, nenhum valor sai
	// do servidor (falha fechada).
	if err := s.store.InsertAudit(r.Context(), events...); err != nil {
		s.logger.Error("auditoria: registrar entrega de segredos", "project", project.Name, "err", err)
		writeAuditFailed(w)
		return
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
	// "meta" é válido como variável, mas o caminho GET .../secrets/meta é a
	// listagem de nomes: um segredo com esse nome não poderia ser lido.
	if key == "meta" {
		writeError(w, http.StatusBadRequest, "invalid_key_name", `"meta" é reservado (é o caminho da listagem de nomes)`)
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
	// O projeto já foi resolvido e a permissão conferida (authorize). O PUT
	// não cria projeto: um nome digitado errado dá 404, não um projeto novo.
	project := projectFrom(r.Context()).project

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

	// A nova versão e o evento de auditoria entram na mesma transação: sem
	// registro, a gravação é desfeita (decisão 7).
	var version int
	err = s.store.InTx(r.Context(), func(tx Store) error {
		var err error
		version, err = tx.InsertSecretVersion(r.Context(), store.SecretRow{
			ProjectID:  project.ID,
			Key:        key,
			Ciphertext: env.Ciphertext,
			Nonce:      env.Nonce,
			WrappedDEK: env.WrappedDEK,
			DEKNonce:   env.DEKNonce,
		})
		if err != nil {
			return err
		}
		e := s.event(r, "secret.write", store.AuditSuccess)
		e.SecretKey, e.SecretVersion = key, version
		return auditErr(tx.InsertAudit(r.Context(), e))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: registrar gravação de segredo", "project", project.Name, "key", key, "err", err)
		writeAuditFailed(w)
		return
	}
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

type secretMetaItem struct {
	Key       string    `json:"key"`
	Version   int       `json:"version"`
	Versions  int       `json:"versions"`
	UpdatedAt time.Time `json:"updated_at"`
}

type secretsMetaResponse struct {
	Project string           `json:"project"`
	Secrets []secretMetaItem `json:"secrets"`
}

type secretResponse struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

type trashItem struct {
	Key       string    `json:"key"`
	Version   int       `json:"version"`
	DeletedAt time.Time `json:"deleted_at"`
}

type trashResponse struct {
	Project string      `json:"project"`
	Trash   []trashItem `json:"trash"`
}

// handleSecretsMeta lista os nomes e as versões dos segredos, sem os
// valores. Não precisa do cofre aberto: nada é decifrado.
func (s *server) handleSecretsMeta(w http.ResponseWriter, r *http.Request) {
	project := projectFrom(r.Context()).project
	metas, err := s.store.SecretsMeta(r.Context(), project.ID)
	if err != nil {
		s.logger.Error("listar nomes de segredos", "project", project.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	items := make([]secretMetaItem, 0, len(metas))
	for _, m := range metas {
		items = append(items, secretMetaItem{Key: m.Key, Version: m.Version, Versions: m.Versions, UpdatedAt: m.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, secretsMetaResponse{Project: project.Name, Secrets: items})
}

// handleGetSecret devolve o valor de um segredo: a versão atual ou a de
// ?version=N. É a rota de "ver valores", que o desenvolvedor não tem.
func (s *server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	project, key := projectFrom(r.Context()).project, r.PathValue("key")
	version := 0
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid_version", "versão inválida (use um número a partir de 1)")
			return
		}
		version = n
	}
	if s.vault.Sealed() {
		writeSealed(w)
		return
	}

	row, err := s.store.SecretVersion(r.Context(), project.ID, key, version)
	if errors.Is(err, store.ErrNotFound) {
		writeSecretNotFound(w)
		return
	}
	if err != nil {
		s.logger.Error("ler segredo", "project", project.Name, "key", key, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	plaintext, err := s.vault.DecryptSecret(project.ID, row.Key, envelopeOf(row))
	if errors.Is(err, vault.ErrSealed) {
		writeSealed(w)
		return
	}
	if err != nil {
		s.logger.Error("segredo não decifra: possível adulteração no banco",
			"project", project.Name, "key", row.Key, "version", row.Version)
		writeError(w, http.StatusInternalServerError, "decrypt_failed", "não foi possível decifrar o segredo")
		return
	}
	resp := secretResponse{Key: row.Key, Value: string(plaintext), Version: row.Version, CreatedAt: row.CreatedAt}
	clear(plaintext)
	e := s.event(r, "secret.read", store.AuditSuccess)
	e.SecretKey, e.SecretVersion = row.Key, row.Version
	if err := s.store.InsertAudit(r.Context(), e); err != nil {
		s.logger.Error("auditoria: registrar leitura de segredo", "project", project.Name, "key", key, "err", err)
		writeAuditFailed(w)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleTrashSecret manda o segredo para a lixeira (decisão 11): o run
// deixa de entregá-lo, mas ele pode ser restaurado.
func (s *server) handleTrashSecret(w http.ResponseWriter, r *http.Request) {
	s.trashAction(w, r, "secret.trash", Store.TrashSecret, writeSecretNotFound)
}

// handleRestoreSecret tira o segredo da lixeira.
func (s *server) handleRestoreSecret(w http.ResponseWriter, r *http.Request) {
	s.trashAction(w, r, "secret.restore", Store.RestoreSecret, writeNotInTrash)
}

// handlePurgeSecret exclui definitivamente um segredo que está na lixeira
// (só admin e superadmin, decisão 11). Quando o MFA existir, esta ação vai
// pedir o código do autenticador de novo.
func (s *server) handlePurgeSecret(w http.ResponseWriter, r *http.Request) {
	s.trashAction(w, r, "secret.purge", Store.PurgeSecret, writeNotInTrash)
}

// trashAction roda a operação de lixeira e o evento de auditoria na mesma
// transação.
func (s *server) trashAction(w http.ResponseWriter, r *http.Request, action string,
	op func(st Store, ctx context.Context, projectID, key string) (int, error), notFound func(http.ResponseWriter)) {
	project, key := projectFrom(r.Context()).project, r.PathValue("key")
	logMsg := action
	var version int
	err := s.store.InTx(r.Context(), func(tx Store) error {
		var err error
		if version, err = op(tx, r.Context(), project.ID, key); err != nil {
			return err
		}
		e := s.event(r, action, store.AuditSuccess)
		e.SecretKey, e.SecretVersion = key, version
		return auditErr(tx.InsertAudit(r.Context(), e))
	})
	if errors.Is(err, errAudit) {
		s.logger.Error("auditoria: "+action, "project", project.Name, "key", key, "err", err)
		writeAuditFailed(w)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		notFound(w)
		return
	}
	if err != nil {
		s.logger.Error(logMsg, "project", project.Name, "key", key, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	s.logger.Info(logMsg, "project", project.Name, "key", key, "version", version)
	w.WriteHeader(http.StatusNoContent)
}

// handleListTrash lista o que está na lixeira, para restaurar ou excluir.
func (s *server) handleListTrash(w http.ResponseWriter, r *http.Request) {
	project := projectFrom(r.Context()).project
	trashed, err := s.store.ListTrash(r.Context(), project.ID)
	if err != nil {
		s.logger.Error("listar lixeira", "project", project.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}
	items := make([]trashItem, 0, len(trashed))
	for _, t := range trashed {
		items = append(items, trashItem{Key: t.Key, Version: t.Version, DeletedAt: t.DeletedAt})
	}
	writeJSON(w, http.StatusOK, trashResponse{Project: project.Name, Trash: items})
}

func writeSecretNotFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "secret_not_found", "segredo não encontrado")
}

func writeNotInTrash(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "not_in_trash", "o segredo não está na lixeira")
}
