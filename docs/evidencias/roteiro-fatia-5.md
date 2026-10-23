# Roteiro da demonstração: Fatia 5 (cliente completo)

A Fatia 5 completa o CLI: o `envmem login` grava o servidor e a CA em `~/.config/envmem/config.json` (decisão 38), e os subcomandos `secrets`, `members` e `users` substituem o `curl` usado nas fatias anteriores. Valores de segredo e senhas nunca vão como argumento (decisão 48).

Tudo roda no terminal do dev container. São dois terminais: um para o servidor e outro para os comandos.

## Preparação

```sh
make build
make certs                                        # se certs/ ainda não existir
make migrate                                      # aplica as migrações como dono do banco (decisão 42)
./bin/envmem-server create-superadmin admin@empresa.com
KEY=$(./bin/envmem-server keygen)                 # guarde: é a chave-mestra
```

## Terminal 1: servidor

```sh
./bin/envmem-server
```

## Terminal 2: demonstração

### 1. Unseal e login: o config.json

```sh
printf '{"key":"%s"}' "$KEY" | curl -s --cacert certs/ca.crt --data @- https://localhost:8080/v1/unseal
./bin/envmem login --servidor https://localhost:8080 --ca certs/ca.crt admin@empresa.com
cat ~/.config/envmem/config.json
ls -l ~/.config/envmem/
```

Esperado: o `config.json` tem o endereço e o caminho **absoluto** da CA, e os dois arquivos (`config.json` e `token`) têm permissão 600. Daqui em diante, nenhum comando precisa de `--servidor` nem `--ca`.

### 2. Projetos, com o papel

```sh
./bin/envmem projects create demo
./bin/envmem projects create app-prod
./bin/envmem projects list
```

Esperado: os dois projetos, com o papel `superadmin` em cada um.

### 3. Usuário novo e membro do projeto

```sh
./bin/envmem users create dev@empresa.com         # pede a senha temporária duas vezes, sem eco
./bin/envmem users list
./bin/envmem members add --projeto demo dev@empresa.com
./bin/envmem members list --projeto demo
```

Esperado: `dev@empresa.com` aparece como `usuário`, com `senha temporária`, e é `desenvolvedor` no `demo`. Ele não é membro do `app-prod`.

### 4. Gravar uma variável: nome no comando, valor no prompt

```sh
./bin/envmem secrets set --projeto demo DB_PASSWORD
```

Esperado: o CLI pergunta se deve criar a variável, que ainda não existe, e só então pede o valor, duas vezes, sem mostrar na tela. Depois:

```sh
history | tail -3
```

O histórico mostra só `envmem secrets set --projeto demo DB_PASSWORD`, sem o valor.

Num script, o valor vem do stdin, e criar uma variável nova exige `--criar`:

```sh
echo 'chave-da-api' | ./bin/envmem secrets set --projeto demo --valor-stdin API_KEY
echo 'chave-da-api' | ./bin/envmem secrets set --projeto demo --valor-stdin --criar API_KEY
```

Esperado: o primeiro é recusado (pede `--criar`); o segundo grava.

### 5. Listar nomes, ler valores, versões

```sh
./bin/envmem secrets list
./bin/envmem secrets get --projeto demo DB_PASSWORD
```

Esperado: sem `--projeto`, o `list` mostra todos os projetos, com o papel, inclusive o `app-prod`, ainda sem variáveis. Nunca mostra valores. O `get` mostra o valor, e a leitura fica na auditoria.

### 6. Lixeira

```sh
./bin/envmem secrets rm --projeto demo API_KEY
./bin/envmem secrets trash --projeto demo
./bin/envmem secrets restore --projeto demo API_KEY
```

### 7. O mesmo CLI, como desenvolvedor

Num terceiro terminal, com outro `~/.config` para não trocar a sessão do superadmin:

```sh
export XDG_CONFIG_HOME=$(mktemp -d)
./bin/envmem login --servidor https://localhost:8080 --ca certs/ca.crt dev@empresa.com   # troca a senha temporária
./bin/envmem secrets list
./bin/envmem secrets set --projeto demo DB_PASSWORD
./bin/envmem secrets get --projeto demo DB_PASSWORD
./bin/envmem run --projeto demo -- sh -c 'echo "a aplicação recebeu DB_PASSWORD com ${#DB_PASSWORD} caracteres"'
```

Esperado: o desenvolvedor vê só o `demo` (o `app-prod` nem aparece, decisão 6) e só os nomes; o `set` e o `get` dão 403, o `set` antes de pedir o valor; o `run` funciona. Na auditoria, a negação do `set` aparece como `secrets.write` negado: ela vem da consulta à lixeira, que exige a mesma permissão do `PUT` e é feita antes de pedir o valor (decisão 48). O menu do modo interativo (Fatia 5b) vai esconder essas ações, mas quem decide é o servidor, como se vê aqui.

### 8. Remover o usuário

De volta ao terminal 2:

```sh
./bin/envmem users rm dev@empresa.com
./bin/envmem users list
```

Esperado: o CLI pede confirmação (remover não tem volta: sessões e acessos a projetos são apagados); depois, só o superadmin aparece. A auditoria continua com o e-mail do usuário removido nos eventos antigos.

### 9. Auditoria

```sh
curl -s --cacert certs/ca.crt -H "Authorization: Bearer $(cat ~/.config/envmem/token)" 'https://localhost:8080/v1/audit?project=demo'
```

Esperado: `secret.write`, `secret.read`, `secret.trash`, `secret.restore`, `member.set` e as negações do desenvolvedor (`denied`), sempre com a chave e nunca com o valor.

## Saída registrada (23/10/2026, banco temporário, porta 8099)

Executada com um pseudoterminal (o módulo `pty` do Python), que faz o papel do teclado: as respostas digitadas nos prompts sem eco não aparecem, como numa sessão real. O passo 4 rodou dentro de um `bash -i` com `HISTFILE` próprio; o eco das linhas digitadas foi reordenado para ficar como aparece na tela.

```
## 1. unseal e login
{"status":"ok","sealed":false}
$ envmem login --servidor https://localhost:8099 --ca certs/ca.crt admin@empresa.com
Senha:
sessão iniciada; válida até 24/10 01:52
$ cat ~/.config/envmem/config.json
{
  "server": "https://localhost:8099",
  "ca": "/workspaces/envmem/certs/ca.crt"
}
$ ls -l ~/.config/envmem/   (só permissão e nome)
-rw------- config.json
-rw------- token
## 2. projetos
$ envmem projects create demo
projeto demo criado
$ envmem projects create app-prod
projeto app-prod criado
$ envmem projects list
app-prod  superadmin
demo      superadmin
## 3. usuário e membro
$ envmem users create dev@empresa.com
Senha temporária (de 12 a 128 caracteres):
Repita a senha temporária:
usuário dev@empresa.com criado com senha temporária, válida por 72 horas e trocada no primeiro envmem login
$ envmem users list
admin@empresa.com  superadmin
dev@empresa.com    usuário  senha temporária
$ envmem members add --projeto demo dev@empresa.com
dev@empresa.com é desenvolvedor no projeto demo
$ envmem members list --projeto demo
dev@empresa.com  desenvolvedor
## 4. set: nome no comando, valor no prompt
$ envmem secrets set --projeto demo DB_PASSWORD
A variável DB_PASSWORD não existe no projeto demo. Criar? [s/N] s
Valor (não aparece na tela):
Repita o valor:
DB_PASSWORD gravada no projeto demo (versão 1)
$ history
    1  envmem secrets set --projeto demo DB_PASSWORD
    2  history
$ echo 'chave-da-api' | envmem secrets set --projeto demo --valor-stdin API_KEY
envmem: a variável API_KEY não existe no projeto demo (ou está na lixeira); use --criar para gravá-la
$ echo 'chave-da-api' | envmem secrets set --projeto demo --valor-stdin --criar API_KEY
API_KEY gravada no projeto demo (versão 1)
## 5. list e get
$ envmem secrets list
app-prod (superadmin)
  (sem variáveis)

demo (superadmin)
  API_KEY      v1  23/10/2026 17:52
  DB_PASSWORD  v1  23/10/2026 17:52
$ envmem secrets get --projeto demo DB_PASSWORD
S3nh@-do-Banco
## 6. lixeira
$ envmem secrets rm --projeto demo API_KEY
API_KEY foi para a lixeira do projeto demo (desfaça com envmem secrets restore)
$ envmem secrets trash --projeto demo
API_KEY  v1  removida em 23/10/2026 17:52
$ envmem secrets restore --projeto demo API_KEY
API_KEY restaurada no projeto demo
## 7. como desenvolvedor
$ envmem login --servidor https://localhost:8099 --ca certs/ca.crt dev@empresa.com
Senha:
Sua senha é temporária. Escolha uma senha nova.
Nova senha (de 12 a 128 caracteres):
Repita a nova senha:
senha trocada.
sessão iniciada; válida até 24/10 01:52
$ envmem secrets list
demo (desenvolvedor)
  API_KEY      v1  23/10/2026 17:52
  DB_PASSWORD  v1  23/10/2026 17:52
$ envmem secrets set --projeto demo DB_PASSWORD
envmem: servidor respondeu 403 (forbidden): seu papel não permite esta ação
$ envmem secrets get --projeto demo DB_PASSWORD
envmem: servidor respondeu 403 (forbidden): seu papel não permite esta ação
$ envmem run --projeto demo -- sh -c 'echo "a aplicação recebeu DB_PASSWORD com ${#DB_PASSWORD} caracteres"'
a aplicação recebeu DB_PASSWORD com 14 caracteres
## 8. remover o usuário
$ envmem users rm dev@empresa.com
Remover dev@empresa.com? As sessões e os acessos a projetos são apagados, sem como desfazer. [s/N] s
usuário dev@empresa.com removido
$ envmem users list
admin@empresa.com  superadmin
## 9. auditoria do demo (resumida: ação, chave ou usuário afetado, resultado, quem fez)
project.create                   success  admin@empresa.com
member.set      dev@empresa.com  success  admin@empresa.com
secret.write    DB_PASSWORD      success  admin@empresa.com
secret.write    API_KEY          success  admin@empresa.com
secret.read     DB_PASSWORD      success  admin@empresa.com
secret.trash    API_KEY          success  admin@empresa.com
secret.restore  API_KEY          success  admin@empresa.com
secrets.write                    denied   dev@empresa.com
secrets.read                     denied   dev@empresa.com
secret.run      DB_PASSWORD      success  dev@empresa.com
secret.run      API_KEY          success  dev@empresa.com
```

Nessa execução, nem os valores (`S3nh@-do-Banco`, `chave-da-api`) nem as senhas aparecem no log do servidor nem no JSON da auditoria. Os eventos do desenvolvedor continuam com o e-mail dele depois que o usuário foi removido, porque a auditoria guarda cópias (migração 00005).

O fluxo sem terminal (login, `secrets` com `--valor-stdin`, `members` e `users` com `--senha-stdin` e `--sim`) roda automaticamente em `TestEndToEnd` (`make test-integration`); a parte interativa só pode ser conferida com um terminal, como aqui.
