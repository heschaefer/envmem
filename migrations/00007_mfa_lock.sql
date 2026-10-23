-- +goose Up

-- MFA: códigos errados seguidos, desde o último certo. Ao chegar ao limite
-- (10, auth.MFAMaxFailures), o MFA da conta trava e o login é recusado até
-- um superadmin fazer o reset. Só chega ao código quem já acertou a senha,
-- então travar aqui não deixa um estranho bloquear a conta de alguém (o
-- motivo de a decisão 45 não travar contas no login por senha); e uma
-- sequência de códigos errados indica que a senha vazou.
ALTER TABLE user_totp ADD COLUMN failures integer NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE user_totp DROP COLUMN failures;
