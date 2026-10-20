package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// CreateProject cria um projeto com o nome dado. Se o nome já existir, o
// erro é ErrConflict.
func (s *Store) CreateProject(ctx context.Context, name string) (Project, error) {
	const q = `
		INSERT INTO projects (name) VALUES ($1)
		RETURNING id, name, created_at`

	var p Project
	err := s.pool.QueryRow(ctx, q, name).Scan(&p.ID, &p.Name, &p.CreatedAt)
	if isUniqueViolation(err) {
		return Project{}, ErrConflict
	}
	if err != nil {
		return Project{}, fmt.Errorf("store: criar projeto: %w", err)
	}
	return p, nil
}

// ProjectByName devolve o projeto com o nome dado, ou ErrNotFound.
func (s *Store) ProjectByName(ctx context.Context, name string) (Project, error) {
	const q = `SELECT id, name, created_at FROM projects WHERE name = $1`

	var p Project
	err := s.pool.QueryRow(ctx, q, name).Scan(&p.ID, &p.Name, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("store: ler projeto: %w", err)
	}
	return p, nil
}

// ListProjects devolve todos os projetos, em ordem de nome.
func (s *Store) ListProjects(ctx context.Context) ([]Project, error) {
	const q = `SELECT id, name, created_at FROM projects ORDER BY name`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store: listar projetos: %w", err)
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: ler projeto: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listar projetos: %w", err)
	}
	return out, nil
}

// DeleteProject apaga o projeto com o nome dado. Devolve ErrNotFound se ele
// não existir e ErrProjectNotEmpty se ainda tiver segredos. Quem garante a
// segunda regra é o próprio banco (ON DELETE RESTRICT), então não há janela
// entre "conferir que está vazio" e "apagar".
func (s *Store) DeleteProject(ctx context.Context, name string) error {
	const q = `DELETE FROM projects WHERE name = $1`

	tag, err := s.pool.Exec(ctx, q, name)
	if isRestrictViolation(err) {
		return ErrProjectNotEmpty
	}
	if err != nil {
		return fmt.Errorf("store: apagar projeto: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
