package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/heschaefer/envmem/internal/store"
)

// cmdMigrate aplica as migrações pendentes, conectado como dono das tabelas
// (decisão 42). É a única parte do envmem que usa essa credencial, e só
// quando uma versão nova traz migração; o servidor no ar usa o envmem_app.
//
// A URL vem só de DATABASE_MIGRATE_URL, sem flag, pelo mesmo motivo da
// DATABASE_URL: ela contém senha, e argumentos aparecem no "ps".
func cmdMigrate() int {
	url := os.Getenv("DATABASE_MIGRATE_URL")
	if url == "" {
		fmt.Fprintln(os.Stderr, "envmem-server migrate: DATABASE_MIGRATE_URL não definida (URL do usuário dono do banco)")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, err := store.Open(ctx, url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server migrate: %v\n", err)
		return 1
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "envmem-server migrate: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "envmem-server migrate: banco na versão atual")
	return 0
}
