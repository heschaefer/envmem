# CLAUDE.md

Contexto do projeto para o Claude Code. Leia antes de qualquer tarefa.

## O projeto

TCC de Sistemas de Informação (UNIMATER), autor Henryque Schaefer, orientador Prof. Dr. Rafael Rodrigues Barbosa.

Um **gerenciador de segredos auto-hospedado** para equipes de desenvolvimento. Os segredos (senhas de banco, chaves de API) ficam cifrados num servidor central, com controle de acesso por projeto e auditoria. Um CLI busca os segredos e os entrega à aplicação **direto em memória, como variáveis de ambiente, sem escrever nada em disco**.

**Nome: envmem** ("env" de variáveis de ambiente, "mem" de memória). Módulo Go `github.com/heschaefer/envmem`; binários `envmem` (CLI) e `envmem-server`. Não usar "devsecrets" nem o nome antigo "envault" em lugar nenhum.

**Posicionamento:** ferramentas baseadas em git (SOPS, envault-cli) são simples, mas não têm controle de acesso nem auditoria de leitura. Plataformas como HashiCorp Vault e Infisical têm, mas são complexas de operar. Este projeto fica no meio: controle centralizado (papéis, revogação imediata, auditoria) com a simplicidade de um CLI, e nada guardado no repositório, nem cifrado.

## Escopo

**TCC I (até a banca de validação, 30/11 a 05/12/2026):**

- Cofre com envelope encryption e unseal (chave-mestra só em memória)
- Segredos por projeto, com versão
- Autenticação, RBAC por projeto (quatro papéis) e auditoria
- CLI com subcomandos (`login`, `run`, `secrets`) e modo interativo com menus
- TLS 1.3 entre CLI e servidor

**Depois do núcleo, ainda no TCC I se houver tempo:** MFA para superadmin, admin e gestor; Fatia 6 (credenciais dinâmicas para PostgreSQL, decisão 10).

**TCC II (não implementar agora):** prompt próprio do envmem (ver "Modos de uso"), rotação de segredos, tokens de máquina para CI, OIDC/SSO, hardening (mlock, core dumps), comparação com ferramentas de mercado, artigo e defesa.

**Trabalho futuro:** integração com CI/CD (Jenkins), proxy que injeta credenciais, suporte a Windows, GitHub Actions no repositório.

**Fora do escopo:** painel web (o modo interativo do CLI cumpre esse papel); vazamento causado pela própria aplicação (logs, mensagens de erro).

**Recorte de segurança:**
- Proposta: o dev **usa** os segredos sem precisar **tê-los**. Não recebe por mensagem, não guarda em arquivo, não copia e cola. O segredo só existe em memória.
- Ganhos: elimina vazamento por commit e por arquivo esquecido em disco; a rotação é feita num único ponto.
- Na máquina do dev, ele ainda consegue ver o valor (por exemplo, com `envmem run -- printenv`). Nunca afirmar que o sistema "impede o dev de ver". A frase correta é "reduz a exposição".
- Segredos de produção ficam em projetos dos quais o dev não é membro (RBAC).

## Modos de uso do CLI

**Subcomandos diretos (base, usados em scripts e automação):** `envmem login`, `envmem run --projeto X -- comando args`, `envmem secrets ...`. Funcionam sem nenhuma interação.

**Modo interativo (Fatia 5b):** `envmem` sem argumentos abre menus navegáveis pelas setas, com a biblioteca **huh** (Charm, baseada no Bubble Tea). Fluxo: login (se não houver token válido), lista dos projetos do usuário com o papel em cada um, ações permitidas pelo papel. No TCC I, as ações do desenvolvedor são "Rodar um comando" (que usa o mesmo `run` com `syscall.Exec`) e "Ver variáveis disponíveis (só nomes)". Gestor, admin e superadmin veem também as ações de administração. O modo interativo é só uma camada: chama as mesmas funções dos subcomandos. O menu esconde o que o papel não permite, mas **quem decide é o servidor**, que confere cada ação no RBAC.

**Prompt do envmem (TCC II, não implementar):** opção "Entrar no ambiente", que abre um prompt próprio em que cada comando é conferido (recusa `printenv`, `env`, shells), registrado na auditoria e executado direto, sem bash, então `$VARIAVEL` não é expandida. Sem pipes nem redirecionamentos. A sessão termina quando o token expira ou é revogado. Permitido por projeto (`allow_prompt`), desligado em produção. É atrito e rastreabilidade, não barreira: `node -e` ainda contorna.

## Stack (decidida)

**Linguagem e estrutura**
- Go 1.26, um único módulo com dois binários: `cmd/server` (gera `envmem-server`) e `cmd/cli` (gera `envmem`)
- Só biblioteca padrão, exceto onde indicado abaixo

**Servidor**
- HTTP: `net/http` com os padrões do Go 1.22 (`"GET /v1/projects/{project}/secrets"`, `r.PathValue`)
- JSON: `encoding/json`
- Configuração: variáveis de ambiente (`ENVMEM_LISTEN_ADDR`, `DATABASE_URL`, caminhos dos certificados), com flags para sobrescrever. `DATABASE_URL` é o usuário restrito `envmem_app`; `DATABASE_MIGRATE_URL` é o dono das tabelas, usado só por `envmem-server migrate` (as duas sem flag)
- Logs: `log/slog` em JSON
- TLS: `crypto/tls`, **só TLS 1.3** (`MinVersion: tls.VersionTLS13`). Certificados gerados por `scripts/gen-certs.sh` com `openssl`: uma CA própria e o certificado do servidor assinado por ela
- Banco: PostgreSQL 18 via `pgx/v5` e `pgxpool`, com **SQL escrito à mão** (sem ORM, sem sqlc)
- Identificadores: `uuidv7()` nativo do PostgreSQL 18
- Migrações: **goose**, com os arquivos embutidos no binário (`go:embed`). Até a Fatia 3, aplicadas na subida do servidor; a partir da Fatia 4, aplicadas por `envmem-server migrate`, com o usuário dono do banco, e o servidor recusa subir com migração pendente (decisão 42). O goose usa `database/sql`, então a conexão para ele vem de `github.com/jackc/pgx/v5/stdlib`
- Criptografia: `crypto/aes`, `crypto/cipher` (AES-256-GCM) e `crypto/rand`
- Senhas: **argon2id** (`golang.org/x/crypto/argon2`), parâmetros mínimos da OWASP: 19 MiB de memória, 2 iterações, paralelismo 1. Sal aleatório de 16 bytes, guardado junto com os parâmetros e o hash
- Chave-mestra: gerada por `envmem-server keygen`, que imprime 32 bytes aleatórios em base64 **uma única vez**. O servidor nunca grava a chave-mestra

**CLI**
- Subcomandos com `switch` em `os.Args[1]` e um `flag.NewFlagSet` por subcomando (sem cobra)
- Modo interativo: huh v2 (`charm.land/huh/v2`, sobre Bubble Tea v2; a v1 ficava em `github.com/charmbracelet/huh`)
- Injeção: `os/exec` (`LookPath`) e `syscall` (`Exec`). Só Linux e macOS
- Leitura de senha sem eco: `golang.org/x/term` (nos subcomandos) ou campo de senha do huh (no modo interativo)
- Configuração em `~/.config/envmem/config.json` (endereço do servidor e caminho do certificado da CA), gravada no `envmem login`
- Token de sessão em `~/.config/envmem/token`, com permissão 600 (`login` e `logout` entram na Fatia 4). `envmem logout` revoga o token no servidor e apaga o arquivo; se o servidor não responder, apaga o arquivo e avisa que a sessão segue válida até vencer. O `run` remove as variáveis `ENVMEM_*` do ambiente antes do exec

**Testes e qualidade**
- `testing` e `net/http/httptest`
- Testes que precisam do banco ficam marcados com `//go:build integration` e usam o PostgreSQL do `docker-compose`. Rodar com `go test -tags integration ./...`. Eles usam `DATABASE_MIGRATE_URL` (dono) para criar schemas temporários, e o `TestEndToEnd` opera como `envmem_app`
- `make check`: `gofmt -l`, `go vet` e `govulncheck`

**Ambiente de desenvolvimento**
- **Dev container** sobre o **Docker Engine instalado dentro do WSL2** (Ubuntu). Sem Docker Desktop (PC da empresa)
- O VS Code abre a pasta do projeto (que fica no sistema de arquivos do WSL, em `~/tcc/envmem`) dentro do container `dev` com a extensão Dev Containers
- `.devcontainer/Dockerfile`: imagem `golang:1.26`, `CGO_ENABLED=0`, `psql`, `openssl`, `make`, goose, govulncheck e Claude Code; usuário comum `dev` (não root)
- `docker-compose.yml` na raiz: serviços `db` (PostgreSQL 18) e `dev`. O banco sobe junto com o dev container; dentro do container, o host do banco é `db`, e as URLs já vêm em `DATABASE_URL` (envmem_app) e `DATABASE_MIGRATE_URL` (dono). `scripts/db-init/` cria o `envmem_app` na primeira subida com volume vazio (num volume existente, `make db-roles`)
- Na imagem `postgres:18`, o volume de dados é montado em `/var/lib/postgresql` (e não em `/var/lib/postgresql/data`)
- Volumes nomeados guardam o banco (`pgdata`), o cache de módulos Go (`gomod`) e o login do Claude Code (`claude`), que sobrevivem à recriação do container
- O container é descartável; o código não. **Fazer push para o GitHub ao fim de cada passo**
- No Windows, o `syscall.Exec` existe, mas sempre devolve erro ("not supported by windows"): o CLI compila, porém o `run` não funciona. Tudo (servidor, CLI e demonstração) roda no terminal do container
- `Makefile` com os alvos `build`, `certs`, `db-roles`, `migrate`, `run-server`, `test`, `test-integration` e `check` (o banco já está de pé, não precisa de `db-up` dentro do container)
- Git, branch principal `main`. Sem licença por enquanto
- Diagramas: C4 no draw.io (`docs/diagramas/`); diagramas de sequência em Mermaid, dentro dos `.md`

## Arquitetura

**Mecanismo central (o diferencial do TCC):** `envmem run --projeto X -- comando args` busca os segredos do projeto, monta o ambiente (`os.Environ()` mais os segredos), localiza o binário com `exec.LookPath` e chama **`syscall.Exec`**. O processo do CLI é substituído pela aplicação (mesmo PID), que recebe os segredos no `envp`. A aplicação não precisa de nenhum código especial: só lê variáveis de ambiente. Não sobra processo pai guardando os segredos.

**Envelope encryption:** cada versão de segredo tem uma chave de dados (DEK) própria, de 32 bytes. O valor é cifrado com a DEK, e a DEK é cifrada **diretamente pela chave-mestra** (decisão 1), ambos em AES-256-GCM. No banco ficam: valor cifrado, nonce, DEK cifrada e nonce da DEK. A DEK em claro é zerada depois do uso. As duas cifragens usam **AAD** com o projeto e a chave do segredo (com prefixo de tamanho): uma linha movida pelo banco para outro projeto ou outra chave não decifra, o que reforça o RBAC contra adulteração direta no banco. Desde a Fatia 3, o AAD usa o id do projeto (rótulo `envmem/secret/v2`). Uma chave intermediária entre a chave-mestra e as DEKs fica como evolução (facilita a rotação, TCC II).

**Seal/unseal:** o servidor sobe **selado**. O unseal é feito pela rota **`POST /v1/unseal`, sem autenticação** (decisão 2): a própria chave-mestra é a credencial, como no HashiCorp Vault. A chave (32 bytes em base64) fica só em memória, protegida por `sync.RWMutex`. Para saber se a chave está certa, o servidor guarda um **valor de verificação** cifrado com a chave-mestra (tabela `vault_meta`, criado no primeiro unseal); no unseal, tenta decifrá-lo e recusa a chave se falhar. Selado, qualquer operação que precise decifrar devolve **503**. O seal por rota exige autenticação de superadmin (Fatia 4); até lá, selar = reiniciar o servidor.

**Duas credenciais distintas:** "credenciais de acesso" (token de sessão do CLI) e "segredos" (o conteúdo protegido). Não confundir nos nomes, diagramas e textos.

**Token de sessão:** opaco, 32 bytes de `crypto/rand`. O servidor guarda só o hash SHA-256 numa tabela de sessões, com validade de 8 horas. Revogar é apagar a linha.

**Auditoria:** tabela no PostgreSQL, só com inserção. O usuário do banco usado pelo servidor tem apenas `INSERT` e `SELECT` nessa tabela. Isso exige que o servidor não seja dono das tabelas: o dono só é usado pelo `envmem-server migrate` (decisão 42).

## Papéis e permissões

**Modelo:** cada ambiente é um projeto separado (por exemplo, `app-prod` e `app-homo`). Não existe entidade "ambiente" dentro do projeto. Os papéis **globais** (superadmin, admin) ficam no usuário. Os papéis **por projeto** (gestor, desenvolvedor) ficam na tabela de membros (usuário, projeto, papel).

| Ação | Superadmin | Admin | Gestor | Desenvolvedor |
|---|---|---|---|---|
| Criar e remover usuários e admins | Sim | Não | Não | Não |
| Unseal e seal do cofre | Sim | Não | Não | Não |
| Resetar a senha de um usuário (nova senha temporária) | Sim | Não | Não | Não |
| Resetar o MFA de um usuário | Sim | Não | Não | Não |
| Ver auditoria | Toda | Toda | Não | Não |
| Criar e excluir projetos | Todos | Todos | Não | Não |
| Nomear gestores | Todos | Todos | Não | Não |
| Adicionar e remover desenvolvedores | Todos | Todos | Projetos dele | Não |
| Criar, alterar, remover (lixeira) e restaurar variáveis | Todos | Todos | Projetos dele | Não |
| Excluir variáveis definitivamente (esvaziar a lixeira) | Todos | Todos | Não | Não |
| Ver valores das variáveis | Todos | Todos | Projetos dele | Não |
| Listar nomes das variáveis (sem valores) | Todos | Todos | Projetos dele | Projetos atribuídos |
| Usar no `run` | Todos | Todos | Projetos dele | Projetos atribuídos |
| Exige MFA | Sim | Sim | Sim | Não |

**Regras adicionais:**
- O primeiro superadmin é criado por `envmem-server create-superadmin`, que só roda direto no servidor
- Recomenda-se ter pelo menos 2 superadmins. O sistema não deixa remover o último
- Um superadmin não reseta o próprio MFA: precisa de outro. Se só houver um e ele perder o MFA, o reset é feito por `envmem-server reset-mfa`, direto no servidor
- Não há códigos de recuperação de MFA: quem perde o app autenticador pede o reset a um superadmin
- O segredo do TOTP de cada usuário é guardado cifrado pelo cofre

## Regras de segurança (não violar)

- Segredos e tokens **nunca** aparecem em URL, log ou mensagem de erro. Valores vão sempre no corpo da requisição
- A auditoria registra **chaves**, nunca valores
- Só o pacote `vault` decifra. O `store` nunca vê texto em claro
- Nonce novo, gerado com `crypto/rand`, a cada cifragem. Nunca reutilizar
- Zerar chaves em claro (`[]byte`) depois de usadas
- **SQL sempre parametrizado** (`$1`, `$2`). Nunca montar SQL com `fmt.Sprintf` ou concatenação. Onde o PostgreSQL não aceita parâmetro (nomes e senhas em `CREATE ROLE`, na Fatia 6), usar `pgx.Identifier{...}.Sanitize()` para o nome e gerar a senha só com caracteres hexadecimais
- O `.env` é só configuração do servidor (porta, URL do banco). Nunca segredos de projeto
- O `run` não cria arquivos em disco
- A chave-mestra nunca é gravada pelo servidor
- Esconder uma opção no menu não é controle de acesso: toda permissão é conferida no servidor
- No CLI, valores de segredo e senhas **nunca** vão como argumento (histórico do shell, `ps`): no terminal, pedidos duas vezes sem eco; em scripts, pelo stdin (`--valor-stdin`, `--senha-stdin`) (decisão 48)
- Nomes de segredos passam por `internal/envname`: formato POSIX e bloqueio de variáveis que executam código ou trocam binários (`PATH`, `LD_*`, `DYLD_*`, `GIT_*`, `NODE_OPTIONS`, `ENVMEM_*` etc.; `meta` é reservado no `PUT`, porque é o caminho da listagem de nomes). O CLI confere antes de injetar; o servidor confere no `PUT` (Fatia 2). É camada adicional, não barreira completa

## Mapa de arquivos

```
cmd/server/{main, cmd_keygen, cmd_migrate, cmd_superadmin, cmd_reset_password}.go
cmd/cli/{main, cmd_login, cmd_logout, cmd_run, cmd_secrets, cmd_projects, cmd_members, cmd_users, session, password, config, inject, cmdline, interactive, interactive_login, interactive_secrets, interactive_admin}.go
internal/config/{config, tls}.go
internal/vault/{seal, envelope, keys}.go (+ testes)
internal/store/{db, migrate, models, users, sessions, projects, members, secrets, audit, vault_meta}.go
internal/auth/{password, email, token, limiter, rbac}.go (+ testes)
internal/audit/recorder.go
internal/envname/envname.go (+ teste)
internal/api/{router, errors, middleware, authorize, handlers_health, handlers_unseal, handlers_auth, handlers_users, handlers_projects, handlers_members, handlers_secrets, handlers_audit}.go
internal/client/{client, auth, projects, secrets, members, users}.go
migrations/*.sql (goose, numeradas: 00001_..., 00002_...)
scripts/gen-certs.sh, scripts/db-init/01-envmem-app.sql
docs/{arquitetura, decisoes, modelo-de-ameacas, modelo-de-dados}.md, docs/diagramas/, docs/evidencias/
```

## Modelo de dados (proposta inicial)

- `users`: id, email (minúsculas), global_role (superadmin, admin ou nenhum), password_hash (argon2id no formato PHC), temp_password_expires_at (preenchida = senha temporária, decisão 43), totp_secret_enc (quando houver MFA)
- `sessions`: token_hash (PK, SHA-256), user_id, expires_at
- `projects`: id, name, allow_prompt (TCC II)
- `members`: user_id, project_id, role (gestor ou desenvolvedor)
- `secrets`: id, project_id, key, version, ciphertext, nonce, wrapped_dek, dek_nonce, created_at, marcação de lixeira (Fatia 4). Único em (projeto, chave, versão). Guarda as 10 versões mais recentes de cada chave (decisão 11)
- `audit_events`: id, at, user_id (nulo no unseal e em login com e-mail inexistente), user_email, remote_addr, action, project_id, project_name, secret_key (nunca o valor), secret_version, target_user_id, target_email, role, result (`success`, `denied` ou `failure`). Sem chave estrangeira: e-mail e nome do projeto são cópias do momento do evento (migração 00005)
- `vault_meta`: valor de verificação do unseal (cifrado com a chave-mestra) e nonce

## Contrato da API (resumo)

Prefixo `/v1`. Erros sempre em JSON: `{"error": "codigo", "message": "texto"}`. Status usados: 400 (corpo, chave ou nome inválido), 401, 403, 404, 409, 500 (erro interno ou segredo que não decifra), 503 (cofre selado).

| Rota | Uso |
|---|---|
| `GET /health` | Estado do servidor, incluindo `sealed` |
| `POST /unseal` | Unseal com a chave-mestra no corpo, sem autenticação |
| `POST /seal` | Seal (superadmin, a partir da Fatia 4) |
| `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` | Sessão do CLI |
| `GET/POST /users`, `DELETE /users/{u}` | Usuários (superadmin). `{u}` é o id, nunca o e-mail (caminhos vão para o log) |
| `POST /users/{u}/password/reset` | Nova senha temporária no corpo; revoga as sessões do usuário (superadmin) |
| `POST /users/{u}/mfa/reset` | Reset de MFA (superadmin, depois do núcleo) |
| `GET/POST /projects`, `DELETE /projects/{p}` | Projetos (`GET` devolve só os do usuário, com o papel) |
| `GET/POST /projects/{p}/members`, `DELETE /projects/{p}/members/{u}` | Membros e papéis (gestor, admin, superadmin; gestor só mexe com desenvolvedores) |
| `GET /projects/{p}/secrets` | Todos os segredos atuais, com valor (usado pelo `run`) |
| `GET /projects/{p}/secrets/meta` | Chaves e versões, sem valores |
| `GET /projects/{p}/secrets/{key}?version=` | Um segredo |
| `PUT /projects/{p}/secrets/{key}` | Grava nova versão (valor no corpo) |
| `DELETE /projects/{p}/secrets/{key}` | Manda para a lixeira (gestor, admin, superadmin) |
| `POST /projects/{p}/secrets/{key}/restore` | Restaura da lixeira |
| `GET /projects/{p}/trash` | Lista a lixeira (gestor, admin, superadmin) |
| `DELETE /projects/{p}/trash/{key}` | Exclui definitivamente (admin e superadmin) |
| `GET /audit?project=` | Trilha de auditoria (superadmin e admin) |

## Desenvolvimento em fatias

Cada fatia entrega algo funcionando de ponta a ponta:

1. **Esqueleto:** servidor com segredo fixo, CLI com `run` injetando via `syscall.Exec`
2. **Cofre:** PostgreSQL, goose, store, envelope encryption, seal/unseal com valor de verificação
3. **Projetos + TLS**
4. **Auth, RBAC e auditoria**
5. **Cliente completo:** configuração (`config.json`) e restante do CLI (`login`, `logout` e token em arquivo foram antecipados para a Fatia 4)
5b. **Modo interativo** com huh
6. **Meta (decisão 10):** credenciais dinâmicas para PostgreSQL

**Estado atual (23/10/2026):** Fatias 1 a 5b prontas, com push no GitHub: o núcleo do TCC I está completo. A Fatia 5b entregou o modo interativo (decisão 49): `envmem` sem argumentos, com terminal, abre os menus (huh v2); sem sessão válida, formulário de login (no primeiro uso, também servidor e caminho do `ca.crt`), troca da senha temporária e gravação de `config.json` e token pelo mesmo `openSession` do `envmem login`; menu principal com os projetos e o papel, e as ações globais (projetos para admin e superadmin, usuários para superadmin); no projeto, "Rodar um comando" (linha separada por `splitCommand`, sem shell, e `syscall.Exec`) e nomes para todos, e valor, gravar, lixeira e membros para gestor, admin e superadmin. O que cada papel vê fica em `projectActions`, `memberActions` e `globalActions`, com teste; a navegação foi conferida com pseudoterminal no roteiro `docs/evidencias/roteiro-fatia-5b.md`, o último registrado. A Fatia 5 entregou: `config.json` gravado no `envmem login`, só depois do login aceito, com o caminho absoluto da CA, permissão 600 e recusa se outros usuários puderem escrever nele (decisão 38; flag informada > arquivo > `https://localhost:8080`); `projects list` com o papel; `envmem secrets` (`list`, que sem `--projeto` percorre todos os projetos do usuário, `get`, `set`, `rm`, `restore`, `trash`, `purge`); `envmem members` (`list`, `add`, `rm`) e `envmem users` (`list`, `create`, `rm`, `reset-password`), que recebem o e-mail e buscam o id; o `set` recebe só o nome e pede confirmação se a variável é nova ou está na lixeira (`--criar` pelo stdin), e o `users rm` pede confirmação (`--sim` sem terminal) (decisão 48). O `TestEndToEnd` cobre o fluxo sem terminal; a parte interativa foi conferida com pseudoterminal no roteiro `docs/evidencias/roteiro-fatia-5.md`. A Fatia 4 entregou: usuário restrito no banco (`envmem_app`) e `envmem-server migrate` (decisão 42); argon2id, política de senha, `create-superadmin` e `reset-password` no servidor; sessões com token opaco, `envmem login` e `logout` com token em arquivo 600, limite de 10 falhas e 5 minutos; RBAC com permissão declarada em cada rota (`internal/auth/rbac.go`), 403/404 conforme a decisão 6, membros, usuários, `POST /seal`, lixeira e retenção de 10 versões; auditoria com falha fechada (exceto seal e logout) e `GET /audit`. O `TestEndToEnd` (`make test-integration`) cobre login, RBAC, run, auditoria e logout no banco real, operando como `envmem_app`. O roteiro de demonstração da Fatia 4 foi dispensado. Banco de demonstração: rodar `make migrate` (até a 00005) e criar o superadmin com `./bin/envmem-server create-superadmin EMAIL`.

**Próximo:** com o núcleo pronto, o que resta do TCC I é o que vem "depois do núcleo, se houver tempo": o MFA para superadmin, admin e gestor (decisão 36) e, se a decisão 10 (Fatia 6 no TCC I, em aberto) for aceita, as credenciais dinâmicas para PostgreSQL. Discutir a ordem com o Henryque antes de começar.

**Meta para 17/10 (apresentação ao orientador): Fatias 1 e 2.** Simplificações permitidas até lá: projeto como coluna de texto na tabela `secrets` (sem tabela `projects`), sem autenticação, seal só por reinício. Roteiro da demonstração:
1. Servidor sobe selado: `/v1/health` mostra `sealed: true`, e `GET` de segredos devolve 503
2. `POST /v1/unseal` com a chave gerada pelo `keygen`
3. `PUT` do segredo `DB_PASSWORD` no projeto `demo`
4. `psql` mostra o valor ilegível na tabela `secrets`
5. `envmem run --verbose --projeto demo -- sh -c 'echo PID=$$ SENHA=$DB_PASSWORD'` mostra a senha e o mesmo PID que o CLI imprimiu antes do exec (sem `--verbose`, o CLI não imprime nada)
6. Reiniciar o servidor: volta selado

Ordem sugerida: Fatia 1 completa (prova do PID); depois Docker + PostgreSQL + goose + store; `envelope.go` com quatro testes (ida e volta, texto adulterado falha, DEK errada falha, chave-mestra errada falha); `seal.go` + rota de unseal + valor de verificação + health; handlers de GET e PUT usando store e vault; teste de ponta a ponta; capturas para `docs/evidencias/`.

## Decisões

**Já tomadas** (registrar cada uma em `docs/decisoes.md`, formato ADR curto: contexto, decisão, consequências): Go e PostgreSQL 18; `syscall.Exec` no `run`; envelope encryption com AES-256-GCM; chave-mestra cifra direto as DEKs (decisão 1); unseal por `POST /v1/unseal` sem autenticação, com valor de verificação (decisão 2); goose; SQL à mão com pgx; uuidv7; slog; configuração do servidor por variáveis de ambiente; TLS 1.3 com CA própria via openssl; argon2id; token opaco (decisão 3); token em arquivo com permissão 600 (decisão 4); papéis superadmin, admin, gestor e desenvolvedor, com cada ambiente como projeto separado; MFA para superadmin, admin e gestor, com reset por superadmin e sem códigos de recuperação; subcomandos diretos mais modo interativo com huh; prompt próprio do envmem no TCC II; shell supervisionado descartado; painel web fora do escopo; configuração do CLI em arquivo; auditoria em tabela append-only; testes de integração com build tag; chave-mestra gerada por `keygen` e nunca gravada; segredos na resposta da API como lista de objetos (`{"key", "value"}`, com espaço para `version`); rota ou método inexistente responde 404 em JSON (não 405); flag `--servidor` no CLI, mantida como sobrescrita quando existir o `config.json`; PID antes do exec só com `--verbose`; bloqueio de nomes de variáveis perigosos (`internal/envname`); AAD com projeto e chave no envelope; `DATABASE_URL` só por variável de ambiente (contém senha; flags aparecem no `ps`); unseal com chave errada responde 401 e com cofre já aberto, 409; segredo que não decifra falha o GET inteiro (500), sem entregar ambiente parcial. Na Fatia 3: migração 00002 recria `secrets` com `project_id` (dados de teste da Fatia 2 descartados); nome de projeto com minúsculas, dígitos e hífen, até 63 caracteres (conferido na API e por CHECK no banco); `PUT` de segredo não cria projeto (404 se não existir); projeto existente sem segredos responde 200 com lista vazia; `DELETE` de projeto com segredos responde 409 (`ON DELETE RESTRICT`), sem antecipar a decisão 11; `GET /projects` devolve todos os projetos, sem papel, até a Fatia 4; TLS 1.3 só entre CLI e servidor (servidor e PostgreSQL ficam na rede interna do compose, sem TLS); servidor só em HTTPS e cliente recusa `http://`; certificado do servidor em `ENVMEM_TLS_CERT` e `ENVMEM_TLS_KEY` (flags `--tls-cert` e `--tls-key`, padrão `certs/`); CLI com `--ca`, que confia só na CA informada (sem `--ca`, CAs do sistema); subcomando `envmem projects` (`list`, `create`, `delete`) já na Fatia 3. Para a Fatia 4: RBAC híbrido (decisão 5), com autenticação global e lista explícita de rotas públicas (`/health`, `/unseal`), cada rota registrada com a permissão que exige numa matriz central (`internal/auth/rbac.go`) e checagem extra no handler só quando a regra depende do corpo; acesso negado a projeto (decisão 6): sem token, 401; quem não é membro recebe 404 com a mesma mensagem de projeto inexistente ("projeto não encontrado ou sem acesso"); membro com papel insuficiente recebe 403; toda negação vai para a auditoria; auditoria (decisão 7) registra eventos de segurança: leitura de valores (uma linha por segredo entregue, com a versão), escrita e remoção de segredos, mudanças de acesso (membros, papéis, projetos, usuários, reset de MFA), login e logout, unseal e seal, e negações do RBAC, com IP de origem; login com e-mail inexistente fica com `user_id` nulo, sem guardar o texto digitado; se o evento não puder ser gravado, a operação é negada (falha fechada), e nas escritas o evento entra na mesma transação (exceção, 22/10/2026: seal e logout acontecem mesmo sem registro, com o erro no log; a auditoria guarda cópias do e-mail, do nome do projeto e do usuário afetado). Também para a Fatia 4 (21/10/2026): dois usuários de banco, com o dono usado só em `envmem-server migrate` (rodado só quando há migração nova) e o servidor com usuário restrito, recusando subir com migração pendente (decisão 42); primeira senha temporária com troca obrigatória no primeiro login, conferida no servidor (decisão 43; quem gera a senha e se ela vence fica para a implementação); projeto nasce sem gestor, nomeado depois por admin ou superadmin (decisão 44); limite de tentativas de login em memória, por conta e por IP, com 429 e `Retry-After`, sem bloquear a conta (decisão 45; 22/10/2026: 10 falhas seguidas e espera de 5 minutos). Em 22/10/2026: senha temporária digitada pelo superadmin, válida por 72 horas (decisão 43); senha esquecida resolvida com nova senha temporária definida pelo superadmin, revogando as sessões (decisão 46); senhas de 12 a 128 caracteres, sem regras de composição (decisão 47); token do CLI em arquivo 600 mantido, com `login` e `logout` antecipados para a Fatia 4 (decisão 4); lixeira de segredos: gestor, admin e superadmin removem e restauram, só admin e superadmin excluem definitivamente (com o código do MFA pedido de novo quando o MFA existir), retenção das 10 versões mais recentes (decisão 11); `PUT` em chave na lixeira grava versão nova e a tira da lixeira, e a lixeira não se esvazia sozinha (decisão 11); único superadmin sem senha: `envmem-server reset-password EMAIL`, só para superadmin, só sem outro superadmin, com senha temporária, revogação de sessões e auditoria (decisão 46). Na Fatia 5 (23/10/2026): valores de segredo e senhas nunca por argumento no CLI, só pelo terminal sem eco ou pelo stdin; `secrets set` com confirmação para variável nova ou na lixeira (`--criar` pelo stdin); `users rm` com confirmação (`--sim` sem terminal); `members` e `users` recebem o e-mail e o CLI busca o id; `secrets purge` sem confirmação até o MFA (decisão 48). Na Fatia 5b (23/10/2026): huh v2 (`charm.land/huh/v2`); o menu tem tudo o que os subcomandos fazem, conforme o papel; primeiro login pelo menu pede servidor e caminho do `ca.crt` (CA não embutida no binário); "Rodar um comando" sem shell, com aspas agrupando e `| & ; < > $` e crase recusados fora das aspas; remover projeto, remover usuário e excluir de vez pedem confirmação no menu, com "não" como padrão (decisão 49).

**Em aberto.** Discutir com o Henryque antes de implementar. Para cada uma, apresentar opções com prós e contras. Ele decide.

10. Fatia 6 (credenciais dinâmicas para PostgreSQL, usuário temporário com `VALID UNTIL`) entra no TCC I?

Nenhuma delas trava as Fatias 1 e 2.

## Como trabalhar comigo

- **Responder em português.**
- **A IA escreve o código, eu reviso e preciso entender.** Ao gerar código, explicar o porquê das partes de segurança. Eu tenho que conseguir defender na banca, linha por linha, `inject.go`, `envelope.go` e `seal.go`.
- **Não tomar decisões de arquitetura sozinho.** Perguntar quando algo não está decidido aqui.
- **Não puxar coisas do TCC II** (prompt do envmem, rotação, OIDC) sem eu pedir. MFA só depois do núcleo pronto.
- **Mudanças pequenas e testáveis**, uma fatia de cada vez, com teste quando fizer sentido, e um commit por passo.
- **Textos do TCC:** sem travessões, fonte Arial, citações indiretas no padrão ABNT, sem exagero de citações, e só citar fontes que eu li.
