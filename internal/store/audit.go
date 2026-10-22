package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Resultados de um evento de auditoria.
const (
	AuditSuccess = "success"
	AuditDenied  = "denied"
	AuditFailure = "failure"
)

// AuditEvent é um evento de auditoria (decisão 7). Registra chaves e
// versões, nunca valores. Campos vazios (ou zero) viram NULL no banco.
type AuditEvent struct {
	At            time.Time // preenchido pelo banco ao gravar
	UserID        string    // quem fez a ação (vazio no unseal e em login com e-mail inexistente)
	UserEmail     string
	RemoteAddr    string // IP de origem
	Action        string
	ProjectID     string
	ProjectName   string
	SecretKey     string
	SecretVersion int
	TargetUserID  string // usuário afetado
	TargetEmail   string
	Role          string // papel atribuído
	Result        string // AuditSuccess, AuditDenied ou AuditFailure
}

// InsertAudit grava os eventos. Vários eventos (por exemplo, um por segredo
// entregue no run) entram juntos ou nenhum entra. O envmem_app só tem
// INSERT e SELECT nesta tabela: depois de gravado, um evento não muda nem
// sai, nem por um servidor comprometido.
func (s *Store) InsertAudit(ctx context.Context, events ...AuditEvent) error {
	const q = `
		INSERT INTO audit_events (user_id, user_email, remote_addr, action, project_id, project_name,
		                          secret_key, secret_version, target_user_id, target_email, role, result)
		VALUES (NULLIF($1, '')::uuid, NULLIF($2, ''), NULLIF($3, '')::inet, $4, NULLIF($5, '')::uuid, NULLIF($6, ''),
		        NULLIF($7, ''), NULLIF($8, 0), NULLIF($9, '')::uuid, NULLIF($10, ''), NULLIF($11, ''), $12)`

	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		for _, e := range events {
			if _, err := tx.Exec(ctx, q, e.UserID, e.UserEmail, e.RemoteAddr, e.Action, e.ProjectID, e.ProjectName,
				e.SecretKey, e.SecretVersion, e.TargetUserID, e.TargetEmail, e.Role, e.Result); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: gravar auditoria: %w", err)
	}
	return nil
}

// AuditFilter filtra a leitura da auditoria.
type AuditFilter struct {
	ProjectName string // vazio: todos os projetos
	Limit       int
}

// ListAudit devolve os eventos mais recentes primeiro.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	const q = `
		SELECT at, coalesce(user_id::text, ''), coalesce(user_email, ''), coalesce(host(remote_addr), ''), action,
		       coalesce(project_id::text, ''), coalesce(project_name, ''), coalesce(secret_key, ''),
		       coalesce(secret_version, 0), coalesce(target_user_id::text, ''), coalesce(target_email, ''),
		       coalesce(role, ''), result
		FROM audit_events
		WHERE $1 = '' OR project_name = $1
		ORDER BY at DESC, id DESC
		LIMIT $2`

	rows, err := s.db.Query(ctx, q, f.ProjectName, f.Limit)
	if err != nil {
		return nil, fmt.Errorf("store: ler auditoria: %w", err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.At, &e.UserID, &e.UserEmail, &e.RemoteAddr, &e.Action, &e.ProjectID, &e.ProjectName,
			&e.SecretKey, &e.SecretVersion, &e.TargetUserID, &e.TargetEmail, &e.Role, &e.Result); err != nil {
			return nil, fmt.Errorf("store: ler auditoria: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: ler auditoria: %w", err)
	}
	return out, nil
}
