-- +goose Up

-- Decisão 43: a senha temporária vence. Uma coluna só substitui o
-- must_change_password da 00003, para não haver dois campos que possam se
-- contradizer:
--   NULL      senha definitiva, escolhida pelo próprio usuário;
--   preenchida senha temporária, digitada pelo superadmin: a troca é
--             obrigatória no primeiro login, e ela não entra depois deste
--             instante (72 horas após ser definida).
ALTER TABLE users DROP COLUMN must_change_password;
ALTER TABLE users ADD COLUMN temp_password_expires_at timestamptz;

-- +goose Down
ALTER TABLE users DROP COLUMN temp_password_expires_at;
ALTER TABLE users ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;
