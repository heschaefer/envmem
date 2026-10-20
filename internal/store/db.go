// Package store acessa o PostgreSQL. Só guarda e devolve material cifrado:
// quem cifra e decifra é o pacote vault. Todo SQL é parametrizado ($1, $2).
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store é o acesso ao banco, com um pool de conexões.
type Store struct {
	pool *pgxpool.Pool
}

// Open conecta ao banco em databaseURL e confere a conexão.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		// O erro de parse pode repetir a URL, que contém a senha do banco.
		return nil, errors.New("store: DATABASE_URL inválida")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: conectar ao banco: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close fecha o pool de conexões.
func (s *Store) Close() {
	s.pool.Close()
}

// isUniqueViolation diz se err é violação de UNIQUE (código 23505).
func isUniqueViolation(err error) bool {
	return hasCode(err, "23505")
}

// isForeignKeyViolation diz se err é violação de chave estrangeira (código
// 23503), como gravar um segredo num projeto que acabou de ser apagado.
func isForeignKeyViolation(err error) bool {
	return hasCode(err, "23503")
}

// isRestrictViolation diz se err é recusa de um ON DELETE RESTRICT (código
// 23001), como apagar um projeto que ainda tem segredos.
func isRestrictViolation(err error) bool {
	return hasCode(err, "23001")
}

func hasCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
