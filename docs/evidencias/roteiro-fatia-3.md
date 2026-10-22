# Roteiro da demonstração: Fatia 3 (projetos + TLS 1.3)

> Desde a Fatia 4 (decisão 42), o servidor não migra sozinho: rode `make migrate` antes de subir o servidor. `DATABASE_URL` passou a ser o usuário restrito `envmem_app`, então o comando de recomeçar do zero abaixo precisa trocar `DATABASE_URL` por `DATABASE_MIGRATE_URL`.

Tudo roda no terminal do dev container. São dois terminais: um para o servidor e outro para os comandos.

## Preparação

```sh
make build
make certs     # CA própria e certificado do servidor em certs/ (uma vez só)
```

O `make certs` roda `scripts/gen-certs.sh`, que gera:

| Arquivo | Conteúdo | Quem usa |
|---|---|---|
| `certs/ca.crt` | certificado da CA própria | CLI e curl (`--ca`, `--cacert`) |
| `certs/ca.key` | chave privada da CA (600) | só para emitir certificados |
| `certs/server.crt` | certificado do servidor, assinado pela CA, válido para `localhost`, `127.0.0.1` e `::1` | servidor |
| `certs/server.key` | chave privada do servidor (600) | servidor |

A pasta `certs/` não vai para o git.

**Banco:** a migração 00002 recria a tabela `secrets` (o AAD passou a usar o id do projeto), então os segredos da Fatia 2 se perdem. O valor de verificação do unseal continua lá: se a chave-mestra da Fatia 2 não estiver mais disponível, recomece do zero:

```sh
psql "$DATABASE_URL" -c 'DROP TABLE IF EXISTS secrets, projects, vault_meta, goose_db_version'
```

Para não repetir o endereço e a CA em todo comando:

```sh
C="--servidor https://localhost:8080 --ca certs/ca.crt"
```

## Terminal 1: servidor

```sh
./bin/envmem-server
```

O servidor só escuta em HTTPS. O certificado vem de `ENVMEM_TLS_CERT` e `ENVMEM_TLS_KEY` (ou `--tls-cert` e `--tls-key`), com padrão em `certs/server.crt` e `certs/server.key`. Sem esses arquivos, ele não sobe.

## Terminal 2: demonstração

### 1. Sem TLS, ou com TLS 1.2: recusado

```sh
curl -s http://localhost:8080/v1/health
curl -s --cacert certs/ca.crt --tlsv1.2 --tls-max 1.2 https://localhost:8080/v1/health; echo "exit $?"
./bin/envmem projects list --servidor http://localhost:8080
./bin/envmem projects list --servidor https://localhost:8080
```

Esperado: o servidor responde que recebeu HTTP numa porta HTTPS; o curl com TLS 1.2 falha no handshake (exit 35); o CLI recusa `http://` antes de conectar; e, sem `--ca`, o CLI recusa o certificado, porque as CAs do sistema não conhecem a CA do envmem.

### 2. TLS 1.3 com a CA do envmem

```sh
echo | openssl s_client -connect localhost:8080 -CAfile certs/ca.crt 2>/dev/null | grep -E '^(New|Verify return code|Protocol)|Negotiated TLS1.3 group'
curl -s --cacert certs/ca.crt https://localhost:8080/v1/health
```

Esperado: `TLSv1.3`, `Verify return code: 0 (ok)` e `{"status":"ok","sealed":true}`.

### 3. Unseal (a chave-mestra agora viaja cifrada)

```sh
KEY=$(./bin/envmem-server keygen)
printf '{"key":"%s"}' "$KEY" | curl -s --cacert certs/ca.crt --data @- https://localhost:8080/v1/unseal
```

### 4. Projetos pelo CLI

```sh
./bin/envmem projects create $C demo
./bin/envmem projects create $C app-prod
./bin/envmem projects create $C App_Prod
./bin/envmem projects list $C
```

Esperado: os dois primeiros são criados, o terceiro é recusado (400, nome fora do formato) e a lista mostra `app-prod` e `demo`.

### 5. PUT só em projeto existente

```sh
printf '{"value":"%s"}' 'S3nh@-do-Banco' | curl -s --cacert certs/ca.crt -X PUT --data @- https://localhost:8080/v1/projects/demo/secrets/DB_PASSWORD
printf '{"value":"%s"}' 'x' | curl -s --cacert certs/ca.crt -X PUT --data @- https://localhost:8080/v1/projects/nao-existe/secrets/DB_PASSWORD
```

Esperado: versão 1 gravada no `demo`; 404 no projeto inexistente (o PUT não cria projeto).

### 6. No banco, o segredo aponta para o projeto pelo id

```sh
psql "$DATABASE_URL" -c "SELECT p.name AS project, s.key, s.version, encode(s.ciphertext, 'hex') AS ciphertext FROM secrets s JOIN projects p ON p.id = s.project_id"
```

### 7. O run, agora sobre TLS 1.3

```sh
./bin/envmem run --verbose $C --projeto demo -- sh -c 'echo PID=$$ SENHA=$DB_PASSWORD'
./bin/envmem run $C --projeto app-prod -- sh -c 'echo "app-prod (vazio): DB_PASSWORD=[$DB_PASSWORD]"'
```

Esperado: o mesmo PID antes e depois do exec, como na Fatia 2. O `app-prod` existe e está vazio, então a aplicação roda sem a variável.

### 8. DELETE só de projeto vazio

```sh
./bin/envmem projects delete $C demo
./bin/envmem projects delete $C app-prod
```

Esperado: 409 no `demo` (tem segredos) e remoção do `app-prod`.

## Saída registrada (20/10/2026, schema temporário, porta 8443)

```
## 1. sem TLS e com TLS 1.2: recusados
Client sent an HTTP request to an HTTPS server.
curl TLS 1.2: exit 35
envmem: endereço do servidor inválido: "http://localhost:8443" (exemplo: https://localhost:8080)
envmem: o certificado do servidor não foi assinado por uma CA confiável (informe o ca.crt do envmem): Get "https://localhost:8443/v1/projects": tls: failed to verify certificate: x509: certificate signed by unknown authority
## 2. TLS 1.3 com a CA do envmem
Peer signature type: ecdsa_secp256r1_sha256
Negotiated TLS1.3 group: X25519MLKEM768
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Protocol: TLSv1.3
Verify return code: 0 (ok)
{"status":"ok","sealed":true}
## 3. unseal
{"status":"ok","sealed":false}
## 4. projetos
projeto demo criado
projeto app-prod criado
envmem: servidor respondeu 400 (invalid_project_name): nome de projeto inválido: use minúsculas, dígitos e hífen, começando por letra ou dígito (até 63 caracteres)
app-prod
demo
## 5. PUT
{"project":"demo","key":"DB_PASSWORD","version":1}
{"error":"project_not_found","message":"projeto não encontrado"}
## 6. psql
 project |     key     | version |                          ciphertext
---------+-------------+---------+--------------------------------------------------------------
 demo    | DB_PASSWORD |       1 | 5d3bb41ce0fc8404dcb2cf8fe47e92a8660eab46138077acdbd620cbff4d
## 7. run
envmem: pid 51477, exec /usr/bin/sh
PID=51477 SENHA=S3nh@-do-Banco
app-prod (vazio): DB_PASSWORD=[]
## 8. DELETE
envmem: servidor respondeu 409 (project_not_empty): o projeto ainda tem segredos; remova-os antes
projeto app-prod removido
```

Avisos registrados no log do servidor nessa execução (um por tentativa recusada no passo 1):

```
http: TLS handshake error from 127.0.0.1:PORTA: client sent an HTTP request to an HTTPS server
http: TLS handshake error from 127.0.0.1:PORTA: tls: client offered only unsupported versions: [303 302 301]
http: TLS handshake error from 127.0.0.1:PORTA: remote error: tls: bad certificate
```

`[303 302 301]` são os códigos de TLS 1.2, 1.1 e 1.0. Nem o valor do segredo nem a chave-mestra aparecem no log.

A troca de chaves negociada (`X25519MLKEM768`) é híbrida: combina X25519 com ML-KEM, um algoritmo pós-quântico. É o padrão do Go 1.26 e do OpenSSL 3.5, sem nenhuma configuração no envmem.

O mesmo fluxo (TLS 1.3, projeto criado pelo CLI, PUT, run com o mesmo PID, reinício selado) roda automaticamente em `TestEndToEnd` (`make test-integration`).
