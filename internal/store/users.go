package store

import (
	"context"
	"errors"
	"fmt"
	"time"

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

	u, err := scanUser(s.db.QueryRow(ctx, q, email, passwordHash))
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

	u, err := scanUser(s.db.QueryRow(ctx, q, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: ler usuário: %w", err)
	}
	return u, nil
}

// ChangePassword grava a nova senha definitiva escolhida pelo usuário (o
// que encerra uma senha temporária) e revoga as outras sessões dele, tudo
// na mesma transação. A sessão keepTokenHash, a de quem está trocando,
// continua valendo. Revogar as demais garante que, se a senha foi trocada
// por suspeita de vazamento, quem estava usando a conta perde o acesso.
func (s *Store) ChangePassword(ctx context.Context, userID, passwordHash string, keepTokenHash []byte) error {
	const update = `UPDATE users SET password_hash = $2, temp_password_expires_at = NULL WHERE id = $1`
	const revoke = `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`

	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, update, userID, passwordHash)
		if err != nil {
			return fmt.Errorf("store: trocar senha: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, revoke, userID, keepTokenHash); err != nil {
			return fmt.Errorf("store: revogar sessões: %w", err)
		}
		return nil
	})
}

// UserByID devolve o usuário com o id dado, ou ErrNotFound.
func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	const q = `
		SELECT id, email, coalesce(global_role, ''), password_hash, temp_password_expires_at, created_at
		FROM users
		WHERE id = $1`

	u, err := scanUser(s.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) || isInvalidText(err) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: ler usuário: %w", err)
	}
	return u, nil
}

// ListUsers devolve todos os usuários, em ordem de e-mail.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	const q = `
		SELECT id, email, coalesce(global_role, ''), password_hash, temp_password_expires_at, created_at
		FROM users
		ORDER BY email`

	rows, err := s.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store: listar usuários: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: ler usuário: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listar usuários: %w", err)
	}
	return out, nil
}

// CreateUser cria um usuário com senha temporária (decisão 43). globalRole
// é RoleSuperadmin, RoleAdmin ou "". E-mail repetido dá ErrConflict.
func (s *Store) CreateUser(ctx context.Context, email, globalRole, passwordHash string, tempExpiresAt time.Time) (User, error) {
	const q = `
		INSERT INTO users (email, global_role, password_hash, temp_password_expires_at)
		VALUES ($1, NULLIF($2, ''), $3, $4)
		RETURNING id, email, coalesce(global_role, ''), password_hash, temp_password_expires_at, created_at`

	u, err := scanUser(s.db.QueryRow(ctx, q, email, globalRole, passwordHash, tempExpiresAt))
	if isUniqueViolation(err) {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, fmt.Errorf("store: criar usuário: %w", err)
	}
	return u, nil
}

// DeleteUser remove o usuário (as sessões e participações dele caem junto,
// pelas chaves estrangeiras). Recusa remover o último superadmin com
// ErrLastSuperadmin. As linhas dos superadmins ficam travadas (FOR UPDATE)
// durante a conferência: duas remoções simultâneas dos dois últimos
// superadmins não conseguem passar as duas.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		supers, err := lockSuperadmins(ctx, tx)
		if err != nil {
			return err
		}
		if len(supers) == 1 && supers[0] == id {
			return ErrLastSuperadmin
		}
		tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
		if isInvalidText(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("store: remover usuário: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ResetPassword define uma senha temporária para o usuário (decisão 46) e
// revoga todas as sessões dele, na mesma transação.
func (s *Store) ResetPassword(ctx context.Context, id, passwordHash string, tempExpiresAt time.Time) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		return resetPassword(ctx, tx, id, passwordHash, tempExpiresAt)
	})
}

// ResetLoneSuperadminPassword é o reset do "envmem-server reset-password"
// (decisão 46): só vale para um superadmin, e só quando não há outro
// superadmin que possa fazer o reset pela API. Devolve ErrNotFound,
// ErrNotSuperadmin ou ErrSuperadminExists quando não se aplica.
func (s *Store) ResetLoneSuperadminPassword(ctx context.Context, email, passwordHash string, tempExpiresAt time.Time) (User, error) {
	var u User
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		supers, err := lockSuperadmins(ctx, tx)
		if err != nil {
			return err
		}
		const q = `
			SELECT id, email, coalesce(global_role, ''), password_hash, temp_password_expires_at, created_at
			FROM users
			WHERE email = $1`
		u, err = scanUser(tx.QueryRow(ctx, q, email))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("store: ler usuário: %w", err)
		}
		if u.GlobalRole != RoleSuperadmin {
			return ErrNotSuperadmin
		}
		if len(supers) > 1 {
			return ErrSuperadminExists
		}
		return resetPassword(ctx, tx, u.ID, passwordHash, tempExpiresAt)
	})
	return u, err
}

func resetPassword(ctx context.Context, tx pgx.Tx, id, passwordHash string, tempExpiresAt time.Time) error {
	const update = `UPDATE users SET password_hash = $2, temp_password_expires_at = $3 WHERE id = $1`
	tag, err := tx.Exec(ctx, update, id, passwordHash, tempExpiresAt)
	if isInvalidText(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: redefinir senha: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
		return fmt.Errorf("store: revogar sessões: %w", err)
	}
	return nil
}

// lockSuperadmins trava as linhas dos superadmins até o fim da transação e
// devolve os ids deles.
func lockSuperadmins(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE global_role = 'superadmin' FOR UPDATE`)
	if err != nil {
		return nil, fmt.Errorf("store: travar superadmins: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("store: travar superadmins: %w", err)
	}
	return ids, nil
}
