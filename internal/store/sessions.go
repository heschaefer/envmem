package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CreateSession grava uma sessão nova (só o hash do token) e aproveita
// para apagar as sessões já vencidas do mesmo usuário, para a tabela não
// acumular linhas mortas.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID string, expiresAt time.Time) error {
	const cleanup = `DELETE FROM sessions WHERE user_id = $1 AND expires_at <= now()`
	const insert = `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`

	if _, err := s.pool.Exec(ctx, cleanup, userID); err != nil {
		return fmt.Errorf("store: limpar sessões vencidas: %w", err)
	}
	if _, err := s.pool.Exec(ctx, insert, tokenHash, userID, expiresAt); err != nil {
		return fmt.Errorf("store: criar sessão: %w", err)
	}
	return nil
}

// UserBySession devolve o dono da sessão com o hash dado, se ela ainda não
// venceu; senão, ErrNotFound. A validade é conferida pelo relógio do banco
// em toda requisição: não há cache, então revogar vale na hora.
func (s *Store) UserBySession(ctx context.Context, tokenHash []byte) (User, error) {
	const q = `
		SELECT u.id, u.email, coalesce(u.global_role, ''), u.password_hash, u.temp_password_expires_at, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()`

	u, err := scanUser(s.pool.QueryRow(ctx, q, tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: ler sessão: %w", err)
	}
	return u, nil
}

// DeleteSession revoga uma sessão. Revogar uma sessão que não existe não é
// erro: o resultado (não existir) é o mesmo.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash); err != nil {
		return fmt.Errorf("store: revogar sessão: %w", err)
	}
	return nil
}
