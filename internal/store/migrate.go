package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/heschaefer/envmem/migrations"
)

var (
	// ErrPendingMigrations indica que o banco não está na versão que este
	// binário espera: falta rodar "envmem-server migrate".
	ErrPendingMigrations = errors.New("store: há migrações pendentes")
	// ErrPrivilegedUser indica que o servidor está conectado com um usuário
	// que consegue alterar ou apagar a auditoria (o dono das tabelas ou um
	// superusuário), em vez do usuário restrito.
	ErrPrivilegedUser = errors.New("store: usuário do banco com privilégios demais")
)

// Migrate aplica as migrações pendentes. Só o "envmem-server migrate" chama,
// conectado como dono das tabelas (decisão 42). O goose usa database/sql,
// então a conexão é uma ponte (stdlib) sobre o mesmo pool do pgx.
func (s *Store) Migrate(ctx context.Context) error {
	provider, closeDB, err := s.goose()
	if err != nil {
		return err
	}
	defer closeDB()
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("store: aplicar migrações: %w", err)
	}
	return nil
}

// CheckMigrated devolve ErrPendingMigrations se alguma migração embutida no
// binário ainda não foi aplicada. Só lê a tabela de controle do goose, então
// funciona com o usuário restrito. Um banco que nunca foi migrado (sem a
// tabela de controle) também conta como pendente.
func (s *Store) CheckMigrated(ctx context.Context) error {
	provider, closeDB, err := s.goose()
	if err != nil {
		return err
	}
	defer closeDB()

	pending, err := provider.HasPending(ctx)
	// Os privilégios do envmem_app vêm das próprias migrações (a partir da
	// 00003). Sem permissão para ler a tabela do goose, o banco está numa
	// versão anterior a elas: também é migração pendente.
	if hasCode(err, "42501") {
		return fmt.Errorf("%w (o usuário não consegue ler a versão do banco)", ErrPendingMigrations)
	}
	if err != nil {
		var exists bool
		if qerr := s.pool.QueryRow(ctx, `SELECT to_regclass('goose_db_version') IS NOT NULL`).Scan(&exists); qerr == nil && !exists {
			return ErrPendingMigrations
		}
		return fmt.Errorf("store: conferir migrações: %w", err)
	}
	if pending {
		return ErrPendingMigrations
	}
	return nil
}

// CheckRestricted devolve ErrPrivilegedUser se o usuário conectado puder
// alterar, apagar ou truncar a auditoria. O dono das tabelas e um
// superusuário sempre podem (o dono consegue devolver a si mesmo qualquer
// privilégio retirado), então o servidor só deve subir com o envmem_app.
// Deve ser chamada depois de CheckMigrated, quando audit_events já existe.
func (s *Store) CheckRestricted(ctx context.Context) error {
	const q = `
		SELECT has_table_privilege(current_user, 'audit_events', 'UPDATE')
		    OR has_table_privilege(current_user, 'audit_events', 'DELETE')
		    OR has_table_privilege(current_user, 'audit_events', 'TRUNCATE')
		    OR pg_get_userbyid(c.relowner) = current_user
		FROM pg_class c
		WHERE c.oid = 'audit_events'::regclass`

	var privileged bool
	if err := s.pool.QueryRow(ctx, q).Scan(&privileged); err != nil {
		return fmt.Errorf("store: conferir privilégios: %w", err)
	}
	if privileged {
		return ErrPrivilegedUser
	}
	return nil
}

// goose prepara o provider do goose sobre o pool. Quem chama fecha a ponte
// database/sql com a função devolvida.
func (s *Store) goose() (*goose.Provider, func() error, error) {
	db := stdlib.OpenDBFromPool(s.pool)
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("store: preparar migrações: %w", err)
	}
	return provider, db.Close, nil
}
