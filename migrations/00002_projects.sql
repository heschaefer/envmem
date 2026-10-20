-- +goose Up

-- Fatia 3: o projeto deixa de ser uma coluna de texto e vira tabela própria.
-- Cada ambiente é um projeto separado (por exemplo, app-prod e app-homo).
-- O nome segue o formato aceito pela API: minúsculas, dígitos e hífen,
-- começando por letra ou dígito, até 63 caracteres.
CREATE TABLE projects (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    name       text        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- A tabela secrets é recriada, e as linhas da Fatia 2 (só de teste) se
-- perdem. Não haveria como migrá-las em SQL: o AAD passa a usar o id do
-- projeto, e recifrar exige a chave-mestra, que nunca chega ao banco.
--
-- ON DELETE RESTRICT: o banco recusa apagar um projeto que ainda tem
-- segredos. A API traduz a recusa em 409.
DROP TABLE secrets;
CREATE TABLE secrets (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid        NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    key         text        NOT NULL,
    version     integer     NOT NULL CHECK (version > 0),
    ciphertext  bytea       NOT NULL,
    nonce       bytea       NOT NULL CHECK (octet_length(nonce) = 12),
    wrapped_dek bytea       NOT NULL,
    dek_nonce   bytea       NOT NULL CHECK (octet_length(dek_nonce) = 12),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, key, version)
);

-- +goose Down
DROP TABLE secrets;
DROP TABLE projects;
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
