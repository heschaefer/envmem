package store

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
)

// SecretRetention é quantas versões de cada segredo ficam guardadas
// (decisão 11). As mais antigas são apagadas a cada versão nova.
const SecretRetention = 10

// InsertSecretVersion grava row como nova versão do segredo (projeto, key).
// O número da versão é calculado no próprio INSERT: maior existente + 1, ou
// 1 se for a primeira. row.Version é ignorado; a versão gravada é devolvida.
// Se outra gravação concorrente pegar o mesmo número, a restrição UNIQUE
// recusa esta e o erro é ErrConflict. Se o projeto tiver sido apagado no
// meio do caminho, a chave estrangeira recusa e o erro é ErrNotFound.
//
// Na mesma transação (decisão 11): se a chave estava na lixeira, sai dela
// (o run passa a entregar o valor novo; o antigo nunca volta), e as versões
// além das SecretRetention mais recentes são apagadas.
func (s *Store) InsertSecretVersion(ctx context.Context, row SecretRow) (int, error) {
	const insert = `
		INSERT INTO secrets (project_id, key, version, ciphertext, nonce, wrapped_dek, dek_nonce)
		SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6
		FROM secrets
		WHERE project_id = $1 AND key = $2
		RETURNING version`
	const untrash = `UPDATE secrets SET deleted_at = NULL WHERE project_id = $1 AND key = $2 AND deleted_at IS NOT NULL`
	const prune = `DELETE FROM secrets WHERE project_id = $1 AND key = $2 AND version <= $3`

	var version int
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, insert,
			row.ProjectID, row.Key, row.Ciphertext, row.Nonce, row.WrappedDEK, row.DEKNonce,
		).Scan(&version)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, untrash, row.ProjectID, row.Key); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, prune, row.ProjectID, row.Key, version-SecretRetention)
		return err
	})
	if isUniqueViolation(err) {
		return 0, ErrConflict
	}
	if isForeignKeyViolation(err) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: gravar segredo: %w", err)
	}
	return version, nil
}

// LatestSecrets devolve a versão mais recente de cada segredo do projeto
// (pelo id), em ordem de chave, sem os que estão na lixeira. Lista vazia se
// o projeto não tiver segredos.
func (s *Store) LatestSecrets(ctx context.Context, projectID string) ([]SecretRow, error) {
	// DISTINCT ON (key) com ORDER BY key, version DESC fica com a primeira
	// linha de cada chave, que é a de maior versão.
	const q = `
		SELECT DISTINCT ON (key)
		       key, version, ciphertext, nonce, wrapped_dek, dek_nonce, created_at
		FROM secrets
		WHERE project_id = $1 AND deleted_at IS NULL
		ORDER BY key, version DESC`

	rows, err := s.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: listar segredos: %w", err)
	}
	defer rows.Close()

	var out []SecretRow
	for rows.Next() {
		r := SecretRow{ProjectID: projectID}
		if err := rows.Scan(&r.Key, &r.Version, &r.Ciphertext, &r.Nonce, &r.WrappedDEK, &r.DEKNonce, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: ler segredo: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listar segredos: %w", err)
	}
	return out, nil
}

// SecretVersion devolve uma versão de um segredo fora da lixeira: a versão
// pedida, ou a mais recente se version for 0. ErrNotFound se não existir.
func (s *Store) SecretVersion(ctx context.Context, projectID, key string, version int) (SecretRow, error) {
	const q = `
		SELECT key, version, ciphertext, nonce, wrapped_dek, dek_nonce, created_at
		FROM secrets
		WHERE project_id = $1 AND key = $2 AND deleted_at IS NULL
		  AND ($3 = 0 OR version = $3)
		ORDER BY version DESC
		LIMIT 1`

	r := SecretRow{ProjectID: projectID}
	err := s.pool.QueryRow(ctx, q, projectID, key, version).
		Scan(&r.Key, &r.Version, &r.Ciphertext, &r.Nonce, &r.WrappedDEK, &r.DEKNonce, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretRow{}, ErrNotFound
	}
	if err != nil {
		return SecretRow{}, fmt.Errorf("store: ler segredo: %w", err)
	}
	return r, nil
}

// SecretsMeta lista os segredos fora da lixeira, sem valor, em ordem de
// chave.
func (s *Store) SecretsMeta(ctx context.Context, projectID string) ([]SecretMeta, error) {
	const q = `
		SELECT key, max(version), count(*), max(created_at)
		FROM secrets
		WHERE project_id = $1 AND deleted_at IS NULL
		GROUP BY key
		ORDER BY key`

	rows, err := s.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: listar segredos: %w", err)
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		if err := rows.Scan(&m.Key, &m.Version, &m.Versions, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: ler segredo: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listar segredos: %w", err)
	}
	return out, nil
}

// TrashSecret manda o segredo, com todas as versões, para a lixeira. O
// run deixa de entregá-lo. ErrNotFound se não houver segredo fora da
// lixeira com essa chave. Devolve a última versão.
func (s *Store) TrashSecret(ctx context.Context, projectID, key string) (int, error) {
	const q = `
		UPDATE secrets SET deleted_at = now()
		WHERE project_id = $1 AND key = $2 AND deleted_at IS NULL
		RETURNING version`
	return s.markTrash(ctx, q, projectID, key)
}

// RestoreSecret tira o segredo da lixeira, com todas as versões.
// ErrNotFound se ele não estiver na lixeira. Devolve a última versão.
func (s *Store) RestoreSecret(ctx context.Context, projectID, key string) (int, error) {
	const q = `
		UPDATE secrets SET deleted_at = NULL
		WHERE project_id = $1 AND key = $2 AND deleted_at IS NOT NULL
		RETURNING version`
	return s.markTrash(ctx, q, projectID, key)
}

// PurgeSecret apaga do banco todas as versões de um segredo que está na
// lixeira (exclusão definitiva, decisão 11). ErrNotFound se ele não estiver
// na lixeira: só se exclui de vez o que já passou pela lixeira. Devolve a
// última versão apagada.
func (s *Store) PurgeSecret(ctx context.Context, projectID, key string) (int, error) {
	const q = `
		DELETE FROM secrets
		WHERE project_id = $1 AND key = $2 AND deleted_at IS NOT NULL
		RETURNING version`
	return s.markTrash(ctx, q, projectID, key)
}

// markTrash roda q (que devolve as versões afetadas) e devolve a maior, ou
// ErrNotFound se nenhuma linha foi afetada.
func (s *Store) markTrash(ctx context.Context, q, projectID, key string) (int, error) {
	rows, err := s.pool.Query(ctx, q, projectID, key)
	if err != nil {
		return 0, fmt.Errorf("store: lixeira: %w", err)
	}
	versions, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		return 0, fmt.Errorf("store: lixeira: %w", err)
	}
	if len(versions) == 0 {
		return 0, ErrNotFound
	}
	return slices.Max(versions), nil
}

// ListTrash lista os segredos na lixeira do projeto, em ordem de chave.
func (s *Store) ListTrash(ctx context.Context, projectID string) ([]TrashedSecret, error) {
	const q = `
		SELECT key, max(version), max(deleted_at)
		FROM secrets
		WHERE project_id = $1 AND deleted_at IS NOT NULL
		GROUP BY key
		ORDER BY key`

	rows, err := s.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: listar lixeira: %w", err)
	}
	defer rows.Close()
	var out []TrashedSecret
	for rows.Next() {
		var t TrashedSecret
		if err := rows.Scan(&t.Key, &t.Version, &t.DeletedAt); err != nil {
			return nil, fmt.Errorf("store: ler lixeira: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listar lixeira: %w", err)
	}
	return out, nil
}
