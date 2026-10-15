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
