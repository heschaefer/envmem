// Package store acessa o PostgreSQL. Só guarda e devolve material cifrado:
// quem cifra e decifra é o pacote vault. Todo SQL é parametrizado ($1, $2).
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store é o acesso ao banco. Fora de transação, db é o pool de conexões;
// dentro de InTx, é a transação, e todos os métodos rodam nela.
type Store struct {
	pool *pgxpool.Pool
	db   dbtx
}

// dbtx é o que o pool e uma transação têm em comum. Begin numa transação
// abre um savepoint, então métodos que já usam transação própria continuam
// funcionando dentro de InTx.
type dbtx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// InTx roda fn numa transação: tudo o que fn fizer com o *Store recebido
// é confirmado junto, ou desfeito junto se fn devolver erro. É assim que um
// evento de auditoria entra na mesma transação da alteração que ele
// registra (decisão 7): se o evento não puder ser gravado, a alteração
// também não acontece.
func (s *Store) InTx(ctx context.Context, fn func(tx *Store) error) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		return fn(&Store{pool: s.pool, db: tx})
	})
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
	return &Store{pool: pool, db: pool}, nil
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

// isInvalidText diz se err é texto inválido para o tipo da coluna (código
// 22P02), como um id que não é uuid vindo da URL: equivale a não encontrar.
func isInvalidText(err error) bool {
	return hasCode(err, "22P02")
}

func hasCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
