-- +goose Up

-- Valor de verificação do unseal: um texto conhecido cifrado com a
-- chave-mestra. Se decifrar, a chave informada no unseal é a certa.
-- Uma linha só (id = 1), criada no primeiro unseal.
CREATE TABLE vault_meta (
    id               smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    check_ciphertext bytea       NOT NULL,
    check_nonce      bytea       NOT NULL CHECK (octet_length(check_nonce) = 12),
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- Cada linha é uma versão de um segredo. Só há material cifrado: o valor
-- (cifrado com a DEK) e a DEK (cifrada com a chave-mestra).
-- Simplificação até a Fatia 3: o projeto é uma coluna de texto, sem tabela
-- projects.
CREATE TABLE secrets (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    project     text        NOT NULL,
    key         text        NOT NULL,
    version     integer     NOT NULL CHECK (version > 0),
    ciphertext  bytea       NOT NULL,
    nonce       bytea       NOT NULL CHECK (octet_length(nonce) = 12),
    wrapped_dek bytea       NOT NULL,
    dek_nonce   bytea       NOT NULL CHECK (octet_length(dek_nonce) = 12),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project, key, version)
);

-- +goose Down
DROP TABLE secrets;
DROP TABLE vault_meta;
