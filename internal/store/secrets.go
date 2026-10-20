package store

import (
	"context"
	"fmt"
)

// InsertSecretVersion grava row como nova versão do segredo (projeto, key).
// O número da versão é calculado no próprio INSERT: maior existente + 1, ou
// 1 se for a primeira. row.Version é ignorado; a versão gravada é devolvida.
// Se outra gravação concorrente pegar o mesmo número, a restrição UNIQUE
// recusa esta e o erro é ErrConflict. Se o projeto tiver sido apagado no
// meio do caminho, a chave estrangeira recusa e o erro é ErrNotFound.
func (s *Store) InsertSecretVersion(ctx context.Context, row SecretRow) (int, error) {
	const q = `
		INSERT INTO secrets (project_id, key, version, ciphertext, nonce, wrapped_dek, dek_nonce)
		SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6
		FROM secrets
		WHERE project_id = $1 AND key = $2
		RETURNING version`

	var version int
	err := s.pool.QueryRow(ctx, q,
		row.ProjectID, row.Key, row.Ciphertext, row.Nonce, row.WrappedDEK, row.DEKNonce,
	).Scan(&version)
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
// (pelo id), em ordem de chave. Lista vazia se o projeto não tiver segredos.
func (s *Store) LatestSecrets(ctx context.Context, projectID string) ([]SecretRow, error) {
	// DISTINCT ON (key) com ORDER BY key, version DESC fica com a primeira
	// linha de cada chave, que é a de maior versão.
	const q = `
		SELECT DISTINCT ON (key)
		       key, version, ciphertext, nonce, wrapped_dek, dek_nonce, created_at
		FROM secrets
		WHERE project_id = $1
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
