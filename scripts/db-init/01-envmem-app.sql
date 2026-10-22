-- Usuário restrito do banco, usado pelo envmem-server no dia a dia
-- (decisão 42). As tabelas pertencem ao usuário dono (envmem), que só é
-- usado pelo "envmem-server migrate"; os privilégios do envmem_app em cada
-- tabela são dados pelas migrações.
--
-- Este arquivo roda de dois jeitos:
--   - sozinho, na primeira subida do PostgreSQL com volume vazio
--     (/docker-entrypoint-initdb.d, ver docker-compose.yml);
--   - por "make db-roles", num banco que já existe.
--
-- A senha abaixo é só do ambiente LOCAL de desenvolvimento, como a do
-- POSTGRES_PASSWORD no docker-compose.yml. Nunca usar fora daqui.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'envmem_app') THEN
        CREATE ROLE envmem_app LOGIN PASSWORD 'envmem_app_dev';
    END IF;
END
$$;
