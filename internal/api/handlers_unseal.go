package api

import (
	"errors"
	"net/http"

	"github.com/heschaefer/envmem/internal/store"
	"github.com/heschaefer/envmem/internal/vault"
)

type unsealRequest struct {
	Key string `json:"key"` // chave-mestra em base64
}

// handleUnseal abre o cofre com a chave-mestra enviada no corpo. Não exige
// autenticação: a própria chave é a credencial (decisão 2).
//
// No primeiro unseal, o banco ainda não tem valor de verificação; ele é
// criado com a chave recebida. Daí em diante, só essa chave abre o cofre.
func (s *server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	var req unsealRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "corpo JSON inválido")
		return
	}
	key, err := vault.DecodeKey(req.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key", err.Error())
		return
	}
	// O cofre guarda uma cópia própria; esta é zerada ao sair.
	defer clear(key)

	meta, err := s.store.GetVaultMeta(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		meta, err = s.initVault(r, key)
	}
	if err != nil {
		s.logger.Error("unseal: ler valor de verificação", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	err = s.vault.Unseal(key, meta.CheckCiphertext, meta.CheckNonce)
	switch {
	case errors.Is(err, vault.ErrWrongKey):
		s.logger.Warn("unseal recusado: chave-mestra incorreta")
		s.recordDenied(r, s.event(r, "vault.unseal", store.AuditFailure))
		writeError(w, http.StatusUnauthorized, "invalid_master_key", "chave-mestra incorreta")
		return
	case errors.Is(err, vault.ErrAlreadyUnsealed):
		writeError(w, http.StatusConflict, "already_unsealed", "o cofre já está aberto")
		return
	case err != nil:
		s.logger.Error("unseal", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "erro interno")
		return
	}

	// A chave já está na memória, e memória não tem rollback: se o registro
	// falhar, o cofre é selado de novo (falha fechada).
	if err := s.store.InsertAudit(r.Context(), s.event(r, "vault.unseal", store.AuditSuccess)); err != nil {
		s.vault.Seal()
		s.logger.Error("auditoria: registrar unseal (cofre selado de novo)", "err", err)
		writeAuditFailed(w)
		return
	}
	s.logger.Info("cofre aberto")
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Sealed: false})
}

// initVault cria e grava o valor de verificação com key. Se outro unseal
// simultâneo gravou antes, usa o valor dele: a chave deste pedido será
// conferida contra esse valor, como num unseal normal.
func (s *server) initVault(r *http.Request, key []byte) (store.VaultMeta, error) {
	ct, nonce, err := vault.NewCheckValue(key)
	if err != nil {
		return store.VaultMeta{}, err
	}
	meta := store.VaultMeta{CheckCiphertext: ct, CheckNonce: nonce}
	inserted, err := s.store.InsertVaultMeta(r.Context(), meta)
	if err != nil {
		return store.VaultMeta{}, err
	}
	if !inserted {
		return s.store.GetVaultMeta(r.Context())
	}
	s.logger.Info("cofre inicializado: valor de verificação criado")
	return meta, nil
}

// handleSeal sela o cofre: a chave-mestra é zerada e descartada da memória,
// e tudo o que precisa decifrar passa a responder 503 até o próximo unseal.
// Só superadmin (a permissão é conferida na rota).
func (s *server) handleSeal(w http.ResponseWriter, r *http.Request) {
	if s.vault.Sealed() {
		writeError(w, http.StatusConflict, "already_sealed", "o cofre já está selado")
		return
	}
	s.vault.Seal()
	// Exceção à falha fechada (decisão 7): selar tira acesso, então o
	// cofre fica selado mesmo que o registro falhe.
	if err := s.store.InsertAudit(r.Context(), s.event(r, "vault.seal", store.AuditSuccess)); err != nil {
		s.logger.Error("auditoria: registrar seal (o cofre foi selado mesmo assim)", "err", err)
	}
	s.logger.Info("cofre selado", "user_id", sessionFrom(r.Context()).user.ID)
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Sealed: true})
}
