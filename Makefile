BIN := bin

.PHONY: build certs db-roles migrate run-server test test-integration check

build:
	go build -o $(BIN)/envmem-server ./cmd/server
	go build -o $(BIN)/envmem ./cmd/cli

# CA própria e certificado do servidor em certs/ (não vão para o git).
certs:
	scripts/gen-certs.sh certs

# Cria o usuário restrito envmem_app num banco que já existe (num volume
# novo, o docker-compose já faz isso sozinho).
db-roles:
	psql "$$DATABASE_MIGRATE_URL" -v ON_ERROR_STOP=1 -f scripts/db-init/01-envmem-app.sql

# Aplica as migrações como dono do banco. Rodar quando houver migração nova,
# antes de subir o servidor (ele não sobe com migração pendente).
migrate:
	go run ./cmd/server migrate

run-server:
	go run ./cmd/server

test:
	go test ./...

# Testes que precisam do PostgreSQL do docker-compose (usam o dono do banco,
# DATABASE_MIGRATE_URL, para criar schemas temporários).
test-integration:
	go test -tags integration ./...

check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt pendente:"; echo "$$out"; exit 1; fi
	go vet ./...
	govulncheck ./...
