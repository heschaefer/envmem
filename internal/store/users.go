package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// scanUser lê as colunas id, email, coalesce(global_role, ”),
// password_hash, temp_password_expires_at e created_at, nessa ordem.
func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.GlobalRole, &u.PasswordHash, &u.TempPasswordExpiresAt, &u.CreatedAt)
	return u, err
}

// CreateFirstSuperadmin cria o primeiro superadmin, com senha definitiva
// escolhida por ele. Devolve ErrSuperadminExists se já houver algum
// superadmin: os seguintes são criados por um superadmin, pela API.
//
// A conferência e a inserção são um único comando. Dois create-superadmin
// exatamente ao mesmo tempo ainda poderiam criar dois, mas o comando roda
// à mão, no servidor, uma vez na vida da instalação.
func (s *Store) CreateFirstSuperadmin(ctx context.Context, email, passwordHash string) (User, error) {
	const q = `
		INSERT INTO users (email, global_role, password_hash)
		SELECT $1, 'superadmin', $2
		WHERE NOT EXISTS (SELECT 1 FROM users WHERE global_role = 'superadmin')
		RETURNING id, email, coalesce(global_role, ''), password_hash, temp_password_expires_at, created_at`

	u, err := scanUser(s.pool.QueryRow(ctx, q, email, passwordHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrSuperadminExists
	}
	if isUniqueViolation(err) {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, fmt.Errorf("store: criar superadmin: %w", err)
	}
	return u, nil
}

// UserByEmail devolve o usuário com o e-mail dado (já normalizado), ou
// ErrNotFound.
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	const q = `
		SELECT id, email, coalesce(global_role, ''), password_hash, temp_password_expires_at, created_at
		FROM users
		WHERE email = $1`

	u, err := scanUser(s.pool.QueryRow(ctx, q, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: ler usuário: %w", err)
	}
	return u, nil
}
