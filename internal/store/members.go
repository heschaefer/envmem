package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Papéis por projeto, guardados na tabela members.
const (
	RoleGestor        = "gestor"
	RoleDesenvolvedor = "desenvolvedor"
)

// Member é um membro de projeto.
type Member struct {
	UserID string
	Email  string
	Role   string
}

// ProjectMembership é um projeto com o papel de um usuário nele.
type ProjectMembership struct {
	Project
	Role string
}

// MemberRole devolve o papel do usuário no projeto, ou ErrNotFound se ele
// não for membro.
func (s *Store) MemberRole(ctx context.Context, projectID, userID string) (string, error) {
	const q = `SELECT role FROM members WHERE project_id = $1 AND user_id = $2`

	var role string
	err := s.db.QueryRow(ctx, q, projectID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) || isInvalidText(err) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: ler papel no projeto: %w", err)
	}
	return role, nil
}

// SetMember torna o usuário membro do projeto com o papel dado, ou troca o
// papel se ele já for membro.
func (s *Store) SetMember(ctx context.Context, projectID, userID, role string) error {
	const q = `
		INSERT INTO members (project_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role`

	_, err := s.db.Exec(ctx, q, projectID, userID, role)
	if isForeignKeyViolation(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: gravar membro: %w", err)
	}
	return nil
}

// ProjectsForMember devolve os projetos de que o usuário é membro, com o
// papel dele em cada um, em ordem de nome.
func (s *Store) ProjectsForMember(ctx context.Context, userID string) ([]ProjectMembership, error) {
	const q = `
		SELECT p.id, p.name, p.created_at, m.role
		FROM members m JOIN projects p ON p.id = m.project_id
		WHERE m.user_id = $1
		ORDER BY p.name`

	rows, err := s.db.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("store: listar projetos do usuário: %w", err)
	}
	defer rows.Close()

	var out []ProjectMembership
	for rows.Next() {
		var pm ProjectMembership
		if err := rows.Scan(&pm.ID, &pm.Name, &pm.CreatedAt, &pm.Role); err != nil {
			return nil, fmt.Errorf("store: ler projeto do usuário: %w", err)
		}
		out = append(out, pm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listar projetos do usuário: %w", err)
	}
	return out, nil
}

// ListMembers devolve os membros do projeto, em ordem de e-mail.
func (s *Store) ListMembers(ctx context.Context, projectID string) ([]Member, error) {
	const q = `
		SELECT u.id, u.email, m.role
		FROM members m JOIN users u ON u.id = m.user_id
		WHERE m.project_id = $1
		ORDER BY u.email`

	rows, err := s.db.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: listar membros: %w", err)
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.Role); err != nil {
			return nil, fmt.Errorf("store: ler membro: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listar membros: %w", err)
	}
	return out, nil
}

// RemoveMember tira o usuário do projeto, ou devolve ErrNotFound se ele não
// for membro.
func (s *Store) RemoveMember(ctx context.Context, projectID, userID string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM members WHERE project_id = $1 AND user_id = $2`, projectID, userID)
	if isInvalidText(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: remover membro: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
