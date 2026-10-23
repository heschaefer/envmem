-- +goose Up

-- MFA (decisão 36): o segredo do TOTP de cada usuário e os desafios do
-- login em duas etapas.

-- Segredo do TOTP, cifrado pelo cofre com o mesmo envelope dos segredos de
-- projeto (DEK própria, cifrada pela chave-mestra) e AAD ligado ao usuário
-- (envmem/totp/v1): quem lê o banco não obtém o segredo, e uma linha
-- copiada para outro usuário não decifra.
--   confirmed_at  nulo enquanto o cadastro não foi confirmado com um código
--                 certo; um cadastro não confirmado não vale para o login
--   last_step     último passo de 30 segundos aceito: cada código vale uma
--                 vez (um código já usado, ou de um passo anterior, é
--                 recusado)
-- Resetar o MFA é apagar a linha; apagar o usuário apaga o MFA dele.
CREATE TABLE user_totp (
    user_id      uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    ciphertext   bytea       NOT NULL,
    nonce        bytea       NOT NULL,
    wrapped_dek  bytea       NOT NULL,
    dek_nonce    bytea       NOT NULL,
    confirmed_at timestamptz,
    last_step    bigint      NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Desafios do login em duas etapas: a senha certa gera um desafio, e o
-- código do MFA o troca pela sessão. Como no token de sessão (decisão 3),
-- só o hash SHA-256 fica no banco. É de uso único (apagado ao dar certo) e
-- curto (expires_at); failures conta os códigos errados neste desafio.
CREATE TABLE mfa_challenges (
    token_hash bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    failures   integer     NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX mfa_challenges_user_id_idx ON mfa_challenges (user_id);

-- Privilégios do envmem_app (decisão 42). UPDATE em user_totp: confirmar o
-- cadastro e avançar last_step; em mfa_challenges: contar falhas.
GRANT SELECT, INSERT, UPDATE, DELETE ON user_totp      TO envmem_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_challenges TO envmem_app;

-- +goose Down
DROP TABLE mfa_challenges;
DROP TABLE user_totp;
