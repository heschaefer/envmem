-- +goose Up

-- Fatia 4: usuários, sessões, membros, auditoria e lixeira de segredos.
--
-- As tabelas pertencem ao usuário que roda o "envmem-server migrate" (o
-- dono). O servidor opera com o envmem_app, que recebe aqui só os
-- privilégios de que precisa em cada tabela (decisão 42). O envmem_app é
-- criado fora das migrações (scripts/db-init), porque migração não deve
-- conter senha.

-- Usuários. Papel global: superadmin, admin ou nenhum (NULL). Os papéis por
-- projeto ficam em members. password_hash guarda o argon2id no formato
-- PHC ($argon2id$v=19$m=...,t=...,p=...$sal$hash), com sal e parâmetros
-- junto. must_change_password marca a senha temporária (decisão 43).
CREATE TABLE users (
    id                   uuid        PRIMARY KEY DEFAULT uuidv7(),
    email                text        NOT NULL UNIQUE
                                     CHECK (email = lower(email) AND position('@' IN email) > 1),
    global_role          text        CHECK (global_role IN ('superadmin', 'admin')),
    password_hash        text        NOT NULL,
    must_change_password boolean     NOT NULL DEFAULT false,
    created_at           timestamptz NOT NULL DEFAULT now()
);

-- Sessões do CLI. Só o hash SHA-256 do token fica no banco (decisão 3):
-- quem lê esta tabela não encontra nenhum token utilizável. Revogar é
-- apagar a linha. Apagar o usuário apaga as sessões dele.
CREATE TABLE sessions (
    token_hash bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- Papéis por projeto. Apagar o projeto ou o usuário apaga a participação.
CREATE TABLE members (
    project_id uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text        NOT NULL CHECK (role IN ('gestor', 'desenvolvedor')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX members_user_id_idx ON members (user_id);

-- Auditoria (decisões 7 e 35). Registra chaves e versões, nunca valores.
-- Não tem chave estrangeira de propósito: o evento precisa sobreviver à
-- remoção do usuário ou do projeto a que se refere. user_id fica nulo no
-- unseal (sem autenticação) e no login com e-mail inexistente.
CREATE TABLE audit_events (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    at             timestamptz NOT NULL DEFAULT now(),
    user_id        uuid,
    remote_addr    inet,
    action         text        NOT NULL,
    project_id     uuid,
    secret_key     text,
    secret_version integer,
    result         text        NOT NULL CHECK (result IN ('success', 'denied', 'failure'))
);
CREATE INDEX audit_events_project_at_idx ON audit_events (project_id, at);
CREATE INDEX audit_events_user_at_idx ON audit_events (user_id, at);

-- Lixeira (decisão 11): as versões de um segredo removido ficam com
-- deleted_at preenchido; o run e as listagens as ignoram.
ALTER TABLE secrets ADD COLUMN deleted_at timestamptz;

-- Privilégios do envmem_app, tabela por tabela (menor privilégio).
-- Nenhuma tabela dá TRUNCATE, e a auditoria não dá UPDATE nem DELETE: nem
-- um servidor comprometido apaga ou altera eventos já registrados.
GRANT SELECT                         ON goose_db_version TO envmem_app; -- conferir migração pendente
GRANT SELECT, INSERT                 ON vault_meta       TO envmem_app; -- o primeiro unseal grava
GRANT SELECT, INSERT, DELETE         ON projects         TO envmem_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON secrets          TO envmem_app; -- UPDATE: lixeira; DELETE: retenção e exclusão definitiva
GRANT SELECT, INSERT, UPDATE, DELETE ON users            TO envmem_app;
GRANT SELECT, INSERT, DELETE         ON sessions         TO envmem_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON members          TO envmem_app;
GRANT SELECT, INSERT                 ON audit_events     TO envmem_app;

-- +goose Down
REVOKE ALL ON goose_db_version, vault_meta, projects, secrets FROM envmem_app;
ALTER TABLE secrets DROP COLUMN deleted_at;
DROP TABLE audit_events;
DROP TABLE members;
DROP TABLE sessions;
DROP TABLE users;
