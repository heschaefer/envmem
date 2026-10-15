BIN := bin

.PHONY: build run-server test test-integration check

build:
	go build -o $(BIN)/envmem-server ./cmd/server
	go build -o $(BIN)/envmem ./cmd/cli

run-server:
	go run ./cmd/server

test:
	go test ./...

# Testes que precisam do PostgreSQL do docker-compose.
test-integration:
	go test -tags integration ./...

check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt pendente:"; echo "$$out"; exit 1; fi
	go vet ./...
	govulncheck ./...
