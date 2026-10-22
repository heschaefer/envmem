-- +goose Up

-- Fatia 4, passo 5: a auditoria guarda cópias (do momento do evento) do
-- e-mail de quem agiu, do nome do projeto e do usuário afetado. Como
-- audit_events não tem chave estrangeira (o evento sobrevive à remoção do
-- usuário ou do projeto), sem essas cópias um evento antigo mostraria só
-- ids que já não correspondem a nada.
--   user_email      quem fez a ação
--   project_name    o projeto (ou o nome pedido, se não existia)
--   target_user_id  usuário afetado (membro adicionado, usuário criado...)
--   target_email
--   role            papel atribuído, quando houver
ALTER TABLE audit_events
    ADD COLUMN user_email     text,
    ADD COLUMN project_name   text,
    ADD COLUMN target_user_id uuid,
    ADD COLUMN target_email   text,
    ADD COLUMN role           text;

-- +goose Down
ALTER TABLE audit_events
    DROP COLUMN user_email,
    DROP COLUMN project_name,
    DROP COLUMN target_user_id,
    DROP COLUMN target_email,
    DROP COLUMN role;
