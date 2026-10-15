package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/heschaefer/envmem/migrations"
)

// Migrate aplica as migrações pendentes. O goose usa database/sql, então a
// conexão é uma ponte (stdlib) sobre o mesmo pool do pgx.
func (s *Store) Migrate(ctx context.Context) error {
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("store: preparar migrações: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("store: aplicar migrações: %w", err)
	}
	return nil
}
