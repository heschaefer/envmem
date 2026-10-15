// Package migrations embute os arquivos SQL do goose no binário do servidor.
package migrations

import "embed"

// FS contém as migrações numeradas (00001_..., 00002_...).
//
//go:embed *.sql
var FS embed.FS
