package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// TOTP é o MFA de um usuário como está no banco (tabela user_totp): só
// material cifrado. Quem cifra e decifra o segredo é o pacote vault.
type TOTP struct {
	UserID     string
	Ciphertext []byte
	Nonce      []byte
	WrappedDEK []byte
	DEKNonce   []byte
	// ConfirmedAt nil indica cadastro iniciado e ainda não confirmado com
	// um código certo: não vale para o login.
	ConfirmedAt *time.Time
	// LastStep é o último passo de 30 segundos aceito (cada código vale
	// uma vez).
	LastStep int64
	// Failures conta os códigos errados seguidos desde o último certo; no
	// limite (auth.MFAMaxFailures), o MFA trava até o reset.
	Failures int
}

// TOTPByUser devolve o MFA do usuário, ou ErrNotFound se ele não tiver.
func (s *Store) TOTPByUser(ctx context.Context, userID string) (TOTP, error) {
	const q = `
		SELECT user_id, ciphertext, nonce, wrapped_dek, dek_nonce, confirmed_at, last_step, failures
		FROM user_totp WHERE user_id = $1`
	var t TOTP
	err := s.db.QueryRow(ctx, q, userID).Scan(&t.UserID, &t.Ciphertext, &t.Nonce, &t.WrappedDEK, &t.DEKNonce, &t.ConfirmedAt, &t.LastStep, &t.Failures)
	if errors.Is(err, pgx.ErrNoRows) || isInvalidText(err) {
		return TOTP{}, ErrNotFound
	}
	if err != nil {
		return TOTP{}, fmt.Errorf("store: ler MFA: %w", err)
	}
	return t, nil
}

// StartTOTP grava um cadastro novo, ainda não confirmado. Substitui um
// cadastro anterior também não confirmado (quem fechou o terminal no meio
// recomeça), mas nunca um confirmado: trocar de app autenticador exige o
// reset por um superadmin (ErrConflict).
func (s *Store) StartTOTP(ctx context.Context, t TOTP) error {
	const q = `
		INSERT INTO user_totp (user_id, ciphertext, nonce, wrapped_dek, dek_nonce)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE
		SET ciphertext = excluded.ciphertext, nonce = excluded.nonce,
		    wrapped_dek = excluded.wrapped_dek, dek_nonce = excluded.dek_nonce,
		    failures = 0, created_at = now()
		WHERE user_totp.confirmed_at IS NULL`
	tag, err := s.db.Exec(ctx, q, t.UserID, t.Ciphertext, t.Nonce, t.WrappedDEK, t.DEKNonce)
	if err != nil {
		return fmt.Errorf("store: gravar MFA: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// ConfirmTOTP confirma o cadastro com o passo do primeiro código certo, que
// já conta como usado. ErrConflict se não houver cadastro pendente (já
// confirmado, ou resetado no meio).
func (s *Store) ConfirmTOTP(ctx context.Context, userID string, step int64) error {
	const q = `
		UPDATE user_totp SET confirmed_at = now(), last_step = $2, failures = 0
		WHERE user_id = $1 AND confirmed_at IS NULL`
	tag, err := s.db.Exec(ctx, q, userID, step)
	if err != nil {
		return fmt.Errorf("store: confirmar MFA: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// UseTOTPStep marca o passo como usado, de forma atômica: só grava se ele
// for posterior ao último usado. Assim, dois logins ao mesmo tempo com o
// mesmo código não passam os dois: o segundo recebe ErrConflict. Um código
// certo zera a contagem de falhas, desde que o MFA não esteja travado: com
// a trava, nem um código certo passa (só o reset destrava).
func (s *Store) UseTOTPStep(ctx context.Context, userID string, step int64, maxFailures int) error {
	const q = `
		UPDATE user_totp SET last_step = $2, failures = 0
		WHERE user_id = $1 AND confirmed_at IS NOT NULL AND last_step < $2 AND failures < $3`
	tag, err := s.db.Exec(ctx, q, userID, step, maxFailures)
	if err != nil {
		return fmt.Errorf("store: usar código do MFA: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// FailTOTP conta um código errado num MFA confirmado e devolve o total de
// falhas seguidas. ErrNotFound se não houver MFA confirmado (no cadastro,
// um código errado não indica ataque: quem cadastra acabou de ler o QR).
func (s *Store) FailTOTP(ctx context.Context, userID string) (int, error) {
	const q = `
		UPDATE user_totp SET failures = failures + 1
		WHERE user_id = $1 AND confirmed_at IS NOT NULL
		RETURNING failures`
	var n int
	err := s.db.QueryRow(ctx, q, userID).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: contar falha do MFA: %w", err)
	}
	return n, nil
}

// DeleteTOTP apaga o MFA do usuário (reset). ErrNotFound se não havia.
func (s *Store) DeleteTOTP(ctx context.Context, userID string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM user_totp WHERE user_id = $1`, userID)
	if isInvalidText(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: apagar MFA: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ManagesAnyProject diz se o usuário é gestor de algum projeto. É o que
// faz um usuário sem papel global precisar de MFA no login.
func (s *Store) ManagesAnyProject(ctx context.Context, userID string) (bool, error) {
	const q = `SELECT EXISTS (SELECT 1 FROM members WHERE user_id = $1 AND role = 'gestor')`
	var ok bool
	if err := s.db.QueryRow(ctx, q, userID).Scan(&ok); err != nil {
		return false, fmt.Errorf("store: conferir se é gestor: %w", err)
	}
	return ok, nil
}

// CreateMFAChallenge grava um desafio de login (só o hash) e aproveita para
// apagar os desafios vencidos do usuário.
func (s *Store) CreateMFAChallenge(ctx context.Context, tokenHash []byte, userID string, expiresAt time.Time) error {
	const cleanup = `DELETE FROM mfa_challenges WHERE user_id = $1 AND expires_at <= now()`
	const insert = `INSERT INTO mfa_challenges (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`
	if _, err := s.db.Exec(ctx, cleanup, userID); err != nil {
		return fmt.Errorf("store: limpar desafios vencidos: %w", err)
	}
	if _, err := s.db.Exec(ctx, insert, tokenHash, userID, expiresAt); err != nil {
		return fmt.Errorf("store: criar desafio: %w", err)
	}
	return nil
}

// MFAChallenge devolve o dono e as falhas de um desafio ainda válido, ou
// ErrNotFound (inexistente, vencido ou já usado). A validade é conferida
// pelo relógio do banco, como nas sessões.
func (s *Store) MFAChallenge(ctx context.Context, tokenHash []byte) (userID string, failures int, err error) {
	const q = `SELECT user_id, failures FROM mfa_challenges WHERE token_hash = $1 AND expires_at > now()`
	err = s.db.QueryRow(ctx, q, tokenHash).Scan(&userID, &failures)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, fmt.Errorf("store: ler desafio: %w", err)
	}
	return userID, failures, nil
}

// FailMFAChallenge conta um código errado no desafio e devolve o total.
func (s *Store) FailMFAChallenge(ctx context.Context, tokenHash []byte) (int, error) {
	const q = `UPDATE mfa_challenges SET failures = failures + 1 WHERE token_hash = $1 RETURNING failures`
	var n int
	err := s.db.QueryRow(ctx, q, tokenHash).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: contar falha do desafio: %w", err)
	}
	return n, nil
}

// DeleteMFAChallenge apaga o desafio: ao dar certo (uso único) ou ao
// esgotar as tentativas. Apagar um que não existe não é erro.
func (s *Store) DeleteMFAChallenge(ctx context.Context, tokenHash []byte) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM mfa_challenges WHERE token_hash = $1`, tokenHash); err != nil {
		return fmt.Errorf("store: apagar desafio: %w", err)
	}
	return nil
}
