# Roteiro da demonstração: Fatias 1 e 2

> Registro da apresentação de 17/10/2026. Desde a Fatia 3, o servidor só aceita HTTPS (TLS 1.3) e os segredos precisam de um projeto criado antes: o roteiro atual está em `roteiro-fatia-3.md`.

Tudo roda no terminal do dev container. São dois terminais: um para o servidor e outro para os comandos.

## Preparação

```sh
make build
```

**Atenção:** o primeiro unseal num banco vazio grava o valor de verificação. Daí em diante, só aquela chave-mestra abre o cofre. Guarde a chave gerada no passo 2. Para recomeçar do zero, apague as tabelas e reinicie o servidor (as migrações recriam tudo):

```sh
psql "$DATABASE_URL" -c 'DROP TABLE secrets, vault_meta, goose_db_version'
```

## Terminal 1: servidor

```sh
./bin/envmem-server
```

## Terminal 2: demonstração

### 1. O servidor sobe selado

```sh
curl -s localhost:8080/v1/health
curl -s localhost:8080/v1/projects/demo/secrets
```

Esperado: `{"status":"ok","sealed":true}` e `{"error":"sealed",...}` (503).

### 2. Unseal com a chave gerada pelo keygen

```sh
KEY=$(./bin/envmem-server keygen)
printf '{"key":"%s"}' "$KEY" | curl -s --data @- localhost:8080/v1/unseal
```

O `printf` é um comando interno do shell, e o `curl` lê o corpo do stdin (`--data @-`). Assim, a chave não aparece na lista de processos (`ps`).

Esperado: `{"status":"ok","sealed":false}`.

### 3. PUT do segredo DB_PASSWORD no projeto demo

```sh
printf '{"value":"%s"}' 'S3nh@-do-Banco' | curl -s -X PUT --data @- localhost:8080/v1/projects/demo/secrets/DB_PASSWORD
```

Esperado: `{"project":"demo","key":"DB_PASSWORD","version":1}`.

### 4. No banco, o valor está ilegível

```sh
psql "$DATABASE_URL" -c "SELECT project, key, version, encode(ciphertext, 'hex') AS ciphertext, octet_length(wrapped_dek) AS dek_bytes FROM secrets"
```

O `ciphertext` tem o tamanho do valor mais 16 bytes da tag do GCM. A DEK cifrada tem 48 bytes (32 da chave mais 16 da tag).

### 5. O run injeta a senha no mesmo PID

```sh
./bin/envmem run --verbose --projeto demo -- sh -c 'echo PID=$$ SENHA=$DB_PASSWORD'
```

Esperado: o PID impresso pelo envmem antes do exec é igual ao `$$` do shell.

### 6. Reiniciar o servidor: volta selado

No terminal 1, `Ctrl+C` e `./bin/envmem-server` de novo. No terminal 2:

```sh
curl -s localhost:8080/v1/health
./bin/envmem run --projeto demo -- true
```

Esperado: `"sealed":true` e `envmem: servidor respondeu 503 (sealed): o cofre está selado`.

## Saída registrada (15/10/2026, banco temporário)

```
## 1. sobe selado
{"status":"ok","sealed":true}
{"error":"sealed","message":"o cofre está selado"}
## 2. unseal
{"status":"ok","sealed":false}
## 3. PUT DB_PASSWORD
{"project":"demo","key":"DB_PASSWORD","version":1}
## 4. psql
 project |     key     | version |                          ciphertext                          | dek_bytes
---------+-------------+---------+--------------------------------------------------------------+-----------
 demo    | DB_PASSWORD |       1 | 9beae86be2da248829f4971952fb26c6fa55f0879cebef52d63a2ed2250b |        48
## 5. run
envmem: pid 120895, exec /usr/bin/sh
PID=120895 SENHA=S3nh@-do-Banco
## 6. reinicia
{"status":"ok","sealed":true}
envmem: servidor respondeu 503 (sealed): o cofre está selado
```

Nos logs do servidor dessa execução, nem o valor do segredo nem a chave-mestra aparecem.

O mesmo roteiro roda automaticamente em `TestEndToEnd` (`make test-integration`).
