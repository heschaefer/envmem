package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GetVaultMeta devolve o valor de verificação do unseal, ou ErrNotFound se
// o cofre ainda não foi inicializado (nenhum unseal até hoje).
func (s *Store) GetVaultMeta(ctx context.Context) (VaultMeta, error) {
	const q = `SELECT check_ciphertext, check_nonce FROM vault_meta WHERE id = 1`

	var m VaultMeta
	err := s.pool.QueryRow(ctx, q).Scan(&m.CheckCiphertext, &m.CheckNonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return VaultMeta{}, ErrNotFound
	}
	if err != nil {
		return VaultMeta{}, fmt.Errorf("store: ler vault_meta: %w", err)
	}
	return m, nil
}

// InsertVaultMeta grava o valor de verificação se ainda não existir.
// Devolve false se já existia: nesse caso nada muda, e quem chamou deve ler
// o valor gravado com GetVaultMeta. Isso resolve dois unseals simultâneos no
// primeiro uso: só o primeiro grava.
func (s *Store) InsertVaultMeta(ctx context.Context, m VaultMeta) (bool, error) {
	const q = `
		INSERT INTO vault_meta (id, check_ciphertext, check_nonce)
		VALUES (1, $1, $2)
		ON CONFLICT (id) DO NOTHING`

	tag, err := s.pool.Exec(ctx, q, m.CheckCiphertext, m.CheckNonce)
	if err != nil {
		return false, fmt.Errorf("store: gravar vault_meta: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
