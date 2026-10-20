# Registro de decisões de arquitetura

Cada decisão segue o formato de ADR (Architecture Decision Record) curto: contexto, decisão e consequências. Os números 1 a 11 vêm das discussões iniciais do projeto; as decisões 10 e 11 ainda estão em aberto. As demais começam no 12 e estão agrupadas por assunto.

**Status possíveis:** aceita (implementada), aceita para fatia futura (decidida, ainda não implementada), substituída (trocada por outra decisão, indicada no texto), descartada e em aberto.

## Índice

| Nº | Decisão | Status |
|---|---|---|
| 1 | Chave-mestra cifra diretamente as DEKs | aceita (Fatia 2) |
| 2 | Unseal por rota sem autenticação, com valor de verificação | aceita (Fatia 2) |
| 3 | Token de sessão opaco | aceita para a Fatia 4 |
| 4 | Token do CLI em arquivo com permissão 600 | aceita para a Fatia 5 |
| 5 | RBAC com permissão declarada na rota | aceita para a Fatia 4 |
| 6 | Acesso negado a projeto: 404 para quem não é membro, 403 para papel insuficiente | aceita para a Fatia 4 |
| 7 | Auditoria de eventos de segurança, com falha fechada | aceita para a Fatia 4 |
| 10 | Credenciais dinâmicas para PostgreSQL no TCC I | em aberto |
| 11 | DELETE de segredo e retenção de versões | em aberto |
| 12 | Go e PostgreSQL 18 | aceita |
| 13 | Injeção por `syscall.Exec` no `run` | aceita (Fatia 1) |
| 14 | Envelope encryption com AES-256-GCM | aceita (Fatia 2) |
| 15 | AAD com projeto e chave do segredo | aceita (Fatia 2), atualizada na Fatia 3 |
| 16 | Chave-mestra gerada por `keygen` e nunca gravada | aceita (Fatia 2) |
| 17 | Respostas do unseal: 401 e 409 | aceita (Fatia 2) |
| 18 | Segredo que não decifra falha a requisição inteira | aceita (Fatia 2) |
| 19 | Acesso ao banco: pgx, SQL à mão, goose e uuidv7 | aceita (Fatia 2) |
| 20 | Configuração do servidor por variáveis de ambiente | aceita |
| 21 | Logs estruturados com slog, sem dados sensíveis | aceita |
| 22 | Formato da API: segredos como lista de objetos e 404 em JSON | aceita (Fatias 1 e 2) |
| 23 | Bloqueio de nomes de variáveis perigosos | aceita |
| 24 | Flag `--servidor` e PID só com `--verbose` | aceita (Fatia 1) |
| 25 | Testes de integração com build tag | aceita (Fatia 2) |
| 26 | Projeto sem segredos responde 404 | substituída pela 29 |
| 27 | Cada ambiente é um projeto; tabela `projects` | aceita (Fatia 3) |
| 28 | Migração 00002 recria a tabela `secrets` | aceita (Fatia 3) |
| 29 | Regras das rotas de projeto e de segredo | aceita (Fatia 3) |
| 30 | DELETE de projeto com segredos responde 409 | aceita (Fatia 3) |
| 31 | TLS 1.3 com CA própria entre CLI e servidor | aceita (Fatia 3) |
| 32 | Subcomando `envmem projects` já na Fatia 3 | aceita (Fatia 3) |
| 33 | Quatro papéis, globais e por projeto | aceita para a Fatia 4 |
| 34 | Senhas com argon2id | aceita para a Fatia 4 |
| 35 | Auditoria em tabela só de inserção | aceita para a Fatia 4 |
| 36 | MFA para superadmin, admin e gestor | aceita para depois do núcleo |
| 37 | Subcomandos diretos e modo interativo com huh | aceita (subcomandos); modo interativo na Fatia 5b |
| 38 | Configuração do CLI em arquivo | aceita para a Fatia 5 |
| 39 | Prompt próprio do envmem no TCC II | aceita para o TCC II |
| 40 | Shell supervisionado | descartada |
| 41 | Painel web | descartada (fora do escopo) |

---

## Cofre e criptografia

### 1. Chave-mestra cifra diretamente as DEKs

**Status:** aceita (Fatia 2)

**Contexto:** no envelope encryption, cada segredo tem uma chave de dados (DEK), e a DEK precisa ser protegida por outra chave. Entre a chave-mestra e as DEKs pode existir uma chave intermediária, que facilita a rotação, mas acrescenta uma camada a mais para implementar e explicar.

**Decisão:** a chave-mestra cifra cada DEK diretamente, sem chave intermediária.

**Consequências:** o modelo fica com dois níveis, simples de demonstrar. Trocar a chave-mestra exige recifrar todas as DEKs. A chave intermediária fica como evolução, junto com a rotação de segredos (TCC II).

### 2. Unseal por rota sem autenticação, com valor de verificação

**Status:** aceita (Fatia 2)

**Contexto:** a chave-mestra não pode ficar gravada no servidor, então precisa ser entregue a ele a cada subida. O servidor também precisa saber se a chave recebida é a certa, sem guardá-la.

**Decisão:** o servidor sobe selado. O unseal é feito por `POST /v1/unseal`, sem autenticação, com a chave-mestra no corpo: a própria chave é a credencial, como no HashiCorp Vault. No primeiro unseal, o servidor cifra um texto conhecido com a chave recebida e grava o resultado na tabela `vault_meta` (o valor de verificação). Nos seguintes, tenta decifrar esse valor e recusa a chave se falhar. A chave fica só em memória, protegida por `sync.RWMutex`. Selado, toda operação que precisa decifrar responde 503.

**Consequências:** reiniciar o servidor equivale a selar. O primeiro unseal fixa a chave-mestra do cofre: daí em diante, só ela abre. O valor de verificação usa um AAD próprio (`envmem/vault-check/v1`), diferente do AAD dos segredos, para que um não possa ser usado no lugar do outro. Como a chave trafega no corpo da requisição, o TLS (decisão 31) é indispensável. O seal por rota fica para a Fatia 4, porque exige autenticação de superadmin.

### 14. Envelope encryption com AES-256-GCM

**Status:** aceita (Fatia 2)

**Contexto:** os segredos ficam no PostgreSQL. Quem tiver acesso ao banco (um backup, um administrador do banco, uma injeção de SQL) não pode conseguir ler os valores.

**Decisão:** cada versão de segredo ganha uma DEK nova, de 32 bytes, gerada com `crypto/rand`. O valor é cifrado com a DEK, e a DEK é cifrada com a chave-mestra, ambos em AES-256-GCM. Cada cifragem usa um nonce novo de 12 bytes, também de `crypto/rand`. No banco ficam o valor cifrado, o nonce, a DEK cifrada e o nonce da DEK. A DEK em claro é zerada depois do uso. Só o pacote `vault` cifra e decifra; o `store` só vê material cifrado.

**Consequências:** o GCM autentica além de cifrar, então qualquer alteração no valor cifrado, no nonce ou na DEK cifrada faz a decifragem falhar. Como cada DEK cifra um único valor e a chave-mestra cifra uma DEK por versão, o número de cifragens por chave fica muito abaixo do limite seguro para nonces aleatórios no GCM.

### 15. AAD com projeto e chave do segredo

**Status:** aceita (Fatia 2), atualizada na Fatia 3

**Contexto:** sem contexto amarrado à cifragem, uma linha cifrada poderia ser copiada no banco de um projeto para outro (por exemplo, de produção para um projeto de desenvolvimento) e seria decifrada normalmente.

**Decisão:** as duas cifragens do envelope usam AAD (dados adicionais autenticados) com um rótulo, o projeto e a chave do segredo, cada campo precedido do seu tamanho. Na Fatia 2, o projeto entrava pelo nome (rótulo `envmem/secret/v1`). Desde a Fatia 3, entra pelo id (rótulo `envmem/secret/v2`).

**Consequências:** uma linha movida no banco para outro projeto ou outra chave não decifra, o que reforça o controle de acesso contra adulteração direta no banco. O prefixo de tamanho evita que pares diferentes gerem os mesmos bytes (por exemplo, `("ab", "c")` e `("a", "bc")`). Com o id, um projeto apagado e recriado com o mesmo nome não abre as linhas do anterior. A troca do nome pelo id tornou ilegíveis os segredos gravados na Fatia 2 (decisão 28).

### 16. Chave-mestra gerada por `keygen` e nunca gravada

**Status:** aceita (Fatia 2)

**Contexto:** a chave-mestra precisa de 32 bytes realmente aleatórios, e quem opera o servidor precisa recebê-la num formato que possa guardar.

**Decisão:** o comando `envmem-server keygen` gera 32 bytes com `crypto/rand` e os imprime em base64 uma única vez. Nem o `keygen` nem o servidor gravam a chave em lugar nenhum.

**Consequências:** guardar a chave é responsabilidade de quem opera. Perder a chave significa perder todos os segredos do cofre, o que é proposital. Na demonstração, a chave é enviada ao unseal pelo stdin do `curl` (`printf ... | curl --data @-`), para não aparecer na lista de processos.

### 17. Respostas do unseal: 401 e 409

**Status:** aceita (Fatia 2)

**Contexto:** o unseal tem três falhas distintas: corpo ou chave em formato inválido, chave que não é a do cofre e cofre já aberto.

**Decisão:** formato inválido responde 400; chave errada responde 401 (`invalid_master_key`); cofre já aberto responde 409 (`already_unsealed`).

**Consequências:** quem opera sabe exatamente o que deu errado, sem que a resposta revele nada sobre a chave correta. O unseal com chave errada é registrado no log como aviso, sem a chave.

### 18. Segredo que não decifra falha a requisição inteira

**Status:** aceita (Fatia 2)

**Contexto:** com o cofre aberto, um segredo que não decifra indica uma linha adulterada ou movida no banco (decisão 15). O servidor pode pular esse segredo e entregar os demais, ou falhar tudo.

**Decisão:** o `GET` dos segredos do projeto responde 500 (`decrypt_failed`) e não entrega nenhum valor. O log registra o projeto, a chave e a versão que falharam, nunca o valor.

**Consequências:** a aplicação nunca roda com um ambiente pela metade, o que esconderia a adulteração. Em troca, um único segredo corrompido impede o `run` do projeto inteiro até ser corrigido.

## Injeção no CLI

### 13. Injeção por `syscall.Exec` no `run`

**Status:** aceita (Fatia 1)

**Contexto:** o CLI precisa entregar os segredos à aplicação sem escrever nada em disco e sem exigir código especial na aplicação. Se o CLI iniciasse a aplicação como processo filho, o processo pai continuaria vivo, com os segredos em memória.

**Decisão:** `envmem run --projeto X -- comando args` busca os segredos, monta o ambiente (`os.Environ()` mais os segredos), localiza o binário com `exec.LookPath` e chama `syscall.Exec`. O processo do CLI é substituído pela aplicação, com o mesmo PID, e os segredos chegam no `envp`.

**Consequências:** não sobra processo pai guardando os segredos, e a aplicação só precisa ler variáveis de ambiente. Um segredo substitui a variável de mesmo nome que já existir no ambiente. Funciona em Linux e macOS; no Windows, o `syscall.Exec` sempre devolve erro, então o `run` não funciona lá. O dev ainda consegue ver os valores na própria máquina (por exemplo, com `envmem run -- printenv`): o sistema reduz a exposição, não a impede.

### 23. Bloqueio de nomes de variáveis perigosos

**Status:** aceita (CLI na Fatia 1, servidor na Fatia 2)

**Contexto:** algumas variáveis de ambiente mudam o binário executado ou fazem o processo executar código, como `PATH`, `LD_PRELOAD` e `NODE_OPTIONS`. Um segredo com um desses nomes, gravado por engano ou por alguém com acesso de escrita, executaria código na máquina de quem roda o `run`.

**Decisão:** o pacote `internal/envname` confere os nomes: formato POSIX (letras, dígitos e `_`, sem começar por dígito) e uma lista de nomes e prefixos bloqueados (`PATH`, `IFS`, `BASH_ENV`, `LD_*`, `DYLD_*`, `GIT_*`, `NODE_OPTIONS`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`, entre outros). O servidor confere no `PUT`, e o CLI confere de novo antes de injetar. O CLI também recusa valores com byte nulo, que o `execve` não aceita.

**Consequências:** é uma camada adicional, não uma barreira completa: a lista não cobre toda variável que algum programa possa interpretar. Se um nome bloqueado chegar ao CLI, nada é executado.

### 24. Flag `--servidor` e PID só com `--verbose`

**Status:** aceita (Fatia 1)

**Contexto:** antes da Fatia 5 não existe arquivo de configuração do CLI. Além disso, para a demonstração, o CLI precisa mostrar que o PID não muda no exec, mas no uso normal não deve imprimir nada além da saída da aplicação.

**Decisão:** o endereço do servidor vem da flag `--servidor`, que continuará valendo como sobrescrita depois que existir o `config.json`. O PID e o caminho do binário só são impressos antes do exec com `--verbose`.

**Consequências:** sem `--verbose`, o `run` é transparente: a saída é só a da aplicação, o que permite usá-lo em scripts.

## Servidor e API

### 12. Go e PostgreSQL 18

**Status:** aceita

**Contexto:** o projeto tem dois binários, servidor e CLI, e precisa de criptografia, HTTP, TLS e chamadas de sistema do Unix, com poucas dependências externas para facilitar a revisão de segurança.

**Decisão:** Go 1.26, num único módulo com dois binários, usando a biblioteca padrão sempre que possível. Banco PostgreSQL 18.

**Consequências:** a biblioteca padrão do Go já tem AES-GCM, TLS 1.3, HTTP com rotas por método e `syscall.Exec`, e os binários são estáticos (`CGO_ENABLED=0`). O PostgreSQL 18 gera `uuidv7()` nativamente. As dependências externas ficam restritas a pgx, goose e, nas próximas fatias, `x/crypto`, `x/term` e huh.

### 19. Acesso ao banco: pgx, SQL à mão, goose e uuidv7

**Status:** aceita (Fatia 2)

**Contexto:** o acesso ao banco precisa ser fácil de auditar linha por linha, porque é onde moram os dados cifrados.

**Decisão:** `pgx/v5` com `pgxpool` e SQL escrito à mão, sempre parametrizado (`$1`, `$2`), sem ORM e sem gerador de código. Migrações com goose, com os arquivos embutidos no binário (`go:embed`) e aplicados na subida do servidor. Identificadores com `uuidv7()` do PostgreSQL.

**Consequências:** cada consulta está visível no código, o que facilita conferir que nenhum SQL é montado por concatenação. O goose usa `database/sql`, então recebe uma ponte (`pgx/v5/stdlib`) sobre o mesmo pool. O UUIDv7 é ordenado pelo tempo de criação, o que favorece os índices.

### 20. Configuração do servidor por variáveis de ambiente

**Status:** aceita

**Contexto:** o servidor roda em container, onde variáveis de ambiente são o meio padrão de configuração. Algumas configurações, como a URL do banco, contêm senha.

**Decisão:** a configuração vem de variáveis de ambiente (`ENVMEM_LISTEN_ADDR`, `DATABASE_URL`, `ENVMEM_TLS_CERT`, `ENVMEM_TLS_KEY`), com flags que as sobrescrevem. A `DATABASE_URL` é a exceção: só vem da variável de ambiente, sem flag.

**Consequências:** argumentos de linha de comando aparecem no `ps` para qualquer usuário da máquina, então a senha do banco nunca vai numa flag. O arquivo `.env` guarda só configuração do servidor, nunca segredos de projeto.

### 21. Logs estruturados com slog, sem dados sensíveis

**Status:** aceita

**Contexto:** os logs do servidor ajudam a investigar problemas, mas são um lugar comum de vazamento de segredos.

**Decisão:** logs em JSON com `log/slog`. Cada requisição registra método, caminho, status e duração, nunca o corpo, a query string nem os cabeçalhos. Erros de decodificação do corpo não são repassados ao log nem ao cliente, porque podem citar trechos do corpo.

**Consequências:** segredos, a chave-mestra e, a partir da Fatia 4, tokens não aparecem no log. Os testes conferem isso para o PUT, o GET e o unseal.

### 22. Formato da API: segredos como lista de objetos e 404 em JSON

**Status:** aceita (Fatias 1 e 2)

**Contexto:** a resposta com segredos vai crescer (por exemplo, com a versão de cada um), e todo erro precisa ter o mesmo formato para o CLI tratar.

**Decisão:** os segredos vêm como lista de objetos (`{"key": ..., "value": ...}`), com espaço para campos novos como `version`. Todo erro segue `{"error": "codigo", "message": "texto"}`, inclusive rota ou método inexistente, que responde 404 em JSON (e não 405 em texto puro). Respostas levam `Cache-Control: no-store`.

**Consequências:** campos novos entram sem quebrar o cliente. O CLI trata todos os erros do mesmo jeito. Nenhum cache intermediário guarda uma resposta com segredos.

### 25. Testes de integração com build tag

**Status:** aceita (Fatia 2)

**Contexto:** parte dos testes precisa do PostgreSQL, que nem sempre está disponível, e não pode apagar os dados da demonstração.

**Decisão:** testes que usam o banco levam `//go:build integration` e rodam com `make test-integration`. Cada teste cria um schema temporário, aplica as migrações nele e o apaga no fim. O roteiro da demonstração roda automaticamente em `TestEndToEnd`.

**Consequências:** `make test` roda sem banco. Os testes de integração não interferem no banco da demonstração nem uns nos outros.

## Projetos (Fatia 3)

### 26. Projeto sem segredos responde 404

**Status:** substituída pela decisão 29 (Fatia 3)

**Contexto:** na Fatia 2 não havia tabela de projetos: o projeto era uma coluna de texto em `secrets`. Um nome digitado errado no `run` faria a aplicação rodar sem nenhuma variável.

**Decisão:** projeto sem segredos era tratado como inexistente e respondia 404.

**Consequências:** a simplificação valeu até existir a tabela `projects`, que permite distinguir projeto inexistente de projeto vazio.

### 27. Cada ambiente é um projeto; tabela `projects`

**Status:** aceita (Fatia 3)

**Contexto:** o mesmo sistema costuma ter ambientes diferentes (produção, homologação), com pessoas diferentes autorizadas em cada um. Uma entidade "ambiente" dentro do projeto acrescentaria um nível a mais em todo o controle de acesso.

**Decisão:** não existe entidade "ambiente": cada ambiente é um projeto separado (por exemplo, `app-prod` e `app-homo`). A tabela `projects` tem id (`uuidv7`), nome único e data de criação. Os segredos apontam para o projeto pelo id. O nome aceita minúsculas, dígitos e hífen, começando por letra ou dígito, até 63 caracteres; a API confere o formato, e o banco confere de novo com um `CHECK`.

**Consequências:** o controle de acesso da Fatia 4 trabalha só com projetos: um dev pode ser membro de `app-homo` sem ser de `app-prod`. O nome aparece na URL e no terminal sem precisar de escape.

### 28. Migração 00002 recria a tabela `secrets`

**Status:** aceita (Fatia 3)

**Contexto:** com a tabela `projects`, a coluna `project` (texto) de `secrets` vira `project_id` (chave estrangeira), e o AAD passa a usar o id (decisão 15). Os segredos já gravados não decifrariam com o AAD novo, e recifrá-los exigiria a chave-mestra, que nunca chega ao banco.

**Decisão:** a migração 00002 cria `projects`, apaga `secrets` e a recria com `project_id`. Os dados da Fatia 2, que eram só de teste, são descartados. A migração 00001 não foi alterada.

**Consequências:** o histórico de migrações continua fiel ao que foi aplicado. Em um sistema com dados reais, a mesma mudança exigiria uma migração feita pelo servidor com o cofre aberto, recifrando cada linha.

### 29. Regras das rotas de projeto e de segredo

**Status:** aceita (Fatia 3); substitui a decisão 26

**Contexto:** com a tabela `projects`, as rotas de segredo precisam tratar projeto inexistente e projeto vazio. A autenticação só chega na Fatia 4.

**Decisão:**
- `GET /v1/projects` lista os projetos, `POST /v1/projects` cria (`{"name": ...}`) e `DELETE /v1/projects/{p}` remove. Nome repetido responde 409, e nome fora do formato, 400.
- O `PUT` de segredo não cria projeto: projeto inexistente responde 404.
- Projeto existente sem segredos responde 200 com lista vazia.
- Rotas de projeto não dependem do cofre, porque não cifram nada, e funcionam com ele selado.
- Até a Fatia 4, `GET /v1/projects` devolve todos os projetos, sem o papel do usuário.

**Consequências:** um nome digitado errado no `PUT` ou no `run` dá 404, em vez de criar um projeto novo ou rodar a aplicação sem variáveis. A listagem filtrada por usuário e com papel entra junto com a autenticação.

### 30. DELETE de projeto com segredos responde 409

**Status:** aceita (Fatia 3)

**Contexto:** apagar um projeto com segredos levanta a mesma questão da decisão 11 (apagar de vez ou só marcar como removido), que está em aberto.

**Decisão:** só é possível apagar projeto vazio. Com segredos, a resposta é 409 (`project_not_empty`). Quem garante a regra é o próprio banco, com `ON DELETE RESTRICT` na chave estrangeira de `secrets`.

**Consequências:** nenhum segredo é apagado em massa por engano, e a decisão 11 não é antecipada. Como a recusa vem do banco, não existe intervalo entre conferir que o projeto está vazio e apagá-lo em que outra requisição poderia gravar um segredo. Se um projeto for apagado no meio de um `PUT`, a chave estrangeira recusa a gravação, e a resposta é 404.

### 32. Subcomando `envmem projects` já na Fatia 3

**Status:** aceita (Fatia 3)

**Contexto:** sem login nem modo interativo (Fatias 5 e 5b), a criação de projetos poderia ficar só na API, via `curl`.

**Decisão:** o CLI ganhou `envmem projects list`, `create NOME` e `delete NOME`. As flags de conexão (`--servidor` e `--ca`) são comuns a todos os subcomandos e ficam em `cmd/cli/config.go`, que na Fatia 5 passa a ler o `config.json`.

**Consequências:** a demonstração da Fatia 3 cria projetos pelo próprio CLI. A Fatia 5 só troca a origem dos valores padrão das flags.

## Transporte (Fatia 3)

### 31. TLS 1.3 com CA própria entre CLI e servidor

**Status:** aceita (Fatia 3)

**Contexto:** entre o CLI e o servidor trafegam os segredos, a chave-mestra (no unseal) e, a partir da Fatia 4, as senhas e os tokens de sessão. Em texto claro, qualquer um na rede os leria. O servidor é auto-hospedado e normalmente fica numa rede interna, sem certificado de uma CA pública.

**Decisão:**
- O servidor só escuta HTTPS, com `MinVersion: tls.VersionTLS13`. Não há porta HTTP.
- `scripts/gen-certs.sh` (`make certs`) gera, com `openssl`, uma CA própria e o certificado do servidor assinado por ela: ECDSA P-256, uso restrito a servidor TLS, válido para `localhost`, `127.0.0.1` e `::1` (os nomes podem ser trocados por `ENVMEM_CERT_SANS`). As chaves privadas ficam com permissão 600.
- O servidor lê o certificado de `ENVMEM_TLS_CERT` e `ENVMEM_TLS_KEY` (flags `--tls-cert` e `--tls-key`, padrão em `certs/`) e não sobe sem eles.
- O CLI exige `https://`, aceita só TLS 1.3 e, com `--ca`, confia apenas na CA informada. Sem `--ca`, usa as CAs do sistema.
- O trecho entre servidor e PostgreSQL fica sem TLS: os dois estão na rede interna do compose, e o que vai para o banco já está cifrado (decisão 14).

**Consequências:** clientes com TLS 1.2 ou anterior são recusados já no handshake. No TLS 1.3 não há suítes de cifra fracas para escolher, e a troca de chaves é sempre efêmera, o que garante sigilo futuro: quem obtiver a chave do servidor depois não decifra o tráfego gravado antes. Com `--ca`, um certificado emitido por uma CA pública para o mesmo nome também é recusado. A chave privada da CA (`ca.key`) permite emitir certificados válidos; fora do ambiente de desenvolvimento, deve ficar fora do servidor. Enquanto não existir o `config.json` (Fatia 5), o `--ca` precisa ser passado em todo comando.

## Fatias seguintes

### 3. Token de sessão opaco

**Status:** aceita para a Fatia 4

**Contexto:** o CLI precisa de uma credencial de acesso depois do login. Tokens autocontidos, como o JWT, dificultam a revogação imediata.

**Decisão:** o token é opaco, com 32 bytes de `crypto/rand`. O servidor guarda só o hash SHA-256 do token, numa tabela de sessões, com validade de 8 horas. Revogar é apagar a linha.

**Consequências:** a revogação vale na hora. Um vazamento da tabela de sessões não entrega tokens utilizáveis. Cada requisição consulta o banco para validar o token.

### 4. Token do CLI em arquivo com permissão 600

**Status:** aceita para a Fatia 5

**Contexto:** o CLI precisa guardar o token entre um comando e outro.

**Decisão:** o token fica em `~/.config/envmem/token`, com permissão 600. `envmem logout` apaga o arquivo e revoga o token no servidor.

**Consequências:** só o próprio usuário lê o token. É o único arquivo que o CLI grava com uma credencial; o `run` continua sem criar arquivos.

### 33. Quatro papéis, globais e por projeto

**Status:** aceita para a Fatia 4

**Contexto:** a equipe precisa de níveis de acesso diferentes, e o acesso a produção precisa ser separado do acesso a homologação.

**Decisão:** superadmin e admin são papéis globais, guardados no usuário. Gestor e desenvolvedor são papéis por projeto, na tabela de membros. As permissões de cada papel estão na tabela do `CLAUDE.md`. O primeiro superadmin é criado por `envmem-server create-superadmin`, direto no servidor, e o sistema não deixa remover o último superadmin.

**Consequências:** segredos de produção ficam em projetos dos quais o dev não é membro. Toda permissão é conferida no servidor, mesmo que o CLI esconda opções no menu.

### 34. Senhas com argon2id

**Status:** aceita para a Fatia 4

**Contexto:** as senhas dos usuários precisam de um hash lento e resistente a ataques com GPU.

**Decisão:** argon2id (`golang.org/x/crypto/argon2`) com os parâmetros mínimos recomendados pela OWASP: 19 MiB de memória, 2 iterações e paralelismo 1, com sal aleatório de 16 bytes guardado junto com os parâmetros e o hash.

**Consequências:** guardar os parâmetros junto com o hash permite aumentá-los no futuro sem invalidar as senhas existentes.

### 35. Auditoria em tabela só de inserção

**Status:** aceita para a Fatia 4

**Contexto:** a auditoria de leitura é um dos diferenciais em relação às ferramentas baseadas em git, e precisa resistir a alterações por parte do próprio servidor.

**Decisão:** os eventos ficam numa tabela do PostgreSQL. O usuário do banco usado pelo servidor tem apenas `INSERT` e `SELECT` nessa tabela. A auditoria registra chaves, nunca valores.

**Consequências:** nem um servidor comprometido consegue apagar ou alterar eventos já registrados. Os eventos registrados estão na decisão 7.

### 5. RBAC com permissão declarada na rota

**Status:** aceita para a Fatia 4 (decidida em 20/10/2026)

**Contexto:** a permissão pode ser conferida dentro de cada handler, com uma chamada explícita, ou na entrada da rota, num ponto central. Nas duas formas quem decide é o servidor; o CLI só leva o pedido. Com a checagem dentro do handler, uma rota nova em que a chamada for esquecida fica aberta.

**Decisão:** modelo híbrido. Um middleware global exige token válido em todas as rotas, exceto as de uma lista explícita de rotas públicas (`GET /v1/health` e `POST /v1/unseal`). Cada rota é registrada junto com a permissão que exige, e um wrapper resolve o usuário, o projeto e o papel, confere a permissão numa matriz central (`internal/auth/rbac.go`, espelho da tabela de papéis) e deixa esses dados no contexto da requisição. O handler só faz checagem adicional quando a regra depende do corpo da requisição, como um gestor que pode adicionar desenvolvedor, mas não nomear gestor.

**Consequências:** a falha é fechada: não há como registrar uma rota sem declarar a permissão. O arquivo de rotas passa a mostrar, rota por rota, quem pode o quê, e um único teste percorre a matriz de rotas e papéis. A busca do projeto pelo nome sai dos handlers e vai para o wrapper. A regra continua sendo por rota: o desenvolvedor pode usar a rota em lote do `run`, que devolve valores, mas não a de um valor isolado. Isso reduz a exposição, não a impede (decisão 13).

### 6. Acesso negado a projeto: 404 para quem não é membro, 403 para papel insuficiente

**Status:** aceita para a Fatia 4 (decidida em 20/10/2026)

**Contexto:** responder sempre 403 revela que o projeto existe, e nomes de projeto podem ser informação sensível (por exemplo, o nome de um cliente). Responder sempre 404 confunde quem é membro do projeto e só não tem o papel exigido.

**Decisão:** sem token válido, a resposta é 401, antes de qualquer consulta ao projeto. Um usuário autenticado que não é membro do projeto recebe 404, com a mesma mensagem de um projeto inexistente ("projeto não encontrado ou sem acesso"). Um membro com papel insuficiente para a ação recebe 403. Superadmin e admin têm acesso a todos os projetos.

**Consequências:** quem não é membro não consegue descobrir quais projetos existem. Quem é membro já sabe que o projeto existe, então o 403 não revela nada e explica melhor o erro. Em todos os casos, a negação é registrada na auditoria (decisão 7): o usuário vê 404, mas a tentativa fica registrada.

### 7. Auditoria de eventos de segurança, com falha fechada

**Status:** aceita para a Fatia 4 (decidida em 20/10/2026)

**Contexto:** registrar só segredos não responde quem deu acesso a quem; registrar toda requisição gera ruído e repete o log do `slog`. Também é preciso definir o que acontece quando o evento não pode ser gravado.

**Decisão:** a auditoria registra os eventos de segurança:
- leitura de valores, no `run` ou de um segredo isolado, com uma linha por segredo entregue e a versão entregue;
- escrita e remoção de segredos;
- mudanças de acesso: membros e papéis, criação e remoção de projetos e de usuários, reset de MFA;
- login (com sucesso ou falha) e logout;
- unseal (com sucesso ou falha) e seal;
- negações do RBAC.

Cada evento guarda também o IP de origem e o resultado (sucesso, negado ou falha). No unseal, que não tem autenticação, e no login com e-mail inexistente, o usuário fica nulo; o texto digitado no login não é guardado. Se o evento não puder ser gravado, a operação é negada (falha fechada), e nas escritas o evento entra na mesma transação da alteração.

**Consequências:** a auditoria responde perguntas de incidente como "quem recebeu a versão 3 da `DB_PASSWORD` antes de ela vazar?". A tabela `audit_events` ganha as colunas `secret_version` e `remote_addr` em relação ao modelo inicial. Não guardar o texto digitado evita que uma senha digitada por engano no campo do e-mail vá parar na auditoria. A falha fechada tem custo baixo porque a auditoria fica no mesmo banco dos segredos: se o banco cair, os segredos já estariam indisponíveis. Se a auditoria um dia for para um serviço externo, essa escolha precisa ser revista. Um `run` de um projeto com muitos segredos gera muitas linhas, o que é o preço do detalhe por versão.

### 36. MFA para superadmin, admin e gestor

**Status:** aceita para depois do núcleo

**Contexto:** os papéis que veem valores ou administram o sistema precisam de uma proteção a mais que a senha.

**Decisão:** TOTP obrigatório para superadmin, admin e gestor. O segredo do TOTP fica cifrado pelo cofre. Não há códigos de recuperação: quem perde o app autenticador pede o reset a um superadmin. Um superadmin não reseta o próprio MFA; se só houver um, o reset é feito por `envmem-server reset-mfa`, direto no servidor.

**Consequências:** a recuperação depende de outro superadmin, por isso se recomenda ter pelo menos dois. O desenvolvedor fica sem MFA, conforme a tabela de papéis.

### 37. Subcomandos diretos e modo interativo com huh

**Status:** subcomandos aceitos (Fatias 1 e 3); modo interativo para a Fatia 5b

**Contexto:** o CLI precisa servir a scripts e automação, sem interação, e também a quem prefere menus em vez de lembrar comandos. Um painel web resolveria o segundo caso, mas aumentaria muito o escopo.

**Decisão:** subcomandos com `switch` em `os.Args[1]` e um `flag.NewFlagSet` por subcomando, sem cobra. `envmem` sem argumentos abre menus navegáveis pelas setas, com a biblioteca huh, que chamam as mesmas funções dos subcomandos.

**Consequências:** o modo interativo é só uma camada: esconder uma opção do menu não é controle de acesso, e o servidor confere cada ação.

### 38. Configuração do CLI em arquivo

**Status:** aceita para a Fatia 5

**Contexto:** repetir o endereço do servidor e a CA em todo comando é inconveniente.

**Decisão:** o `envmem login` grava o endereço do servidor e o caminho do certificado da CA em `~/.config/envmem/config.json`. As flags `--servidor` e `--ca` continuam valendo como sobrescrita.

**Consequências:** o arquivo não guarda segredos nem o token, que fica em arquivo próprio (decisão 4).

### 39. Prompt próprio do envmem no TCC II

**Status:** aceita para o TCC II

**Contexto:** no `run`, o dev pode imprimir os valores (por exemplo, com `printenv`). Um ambiente mais restrito aumentaria o atrito e a rastreabilidade.

**Decisão:** no TCC II, uma opção "Entrar no ambiente" abre um prompt próprio: cada comando é conferido (recusa `printenv`, `env` e shells), registrado na auditoria e executado direto, sem bash, sem pipes e sem redirecionamentos. A sessão acaba quando o token expira ou é revogado. É habilitado por projeto (`allow_prompt`) e fica desligado em produção.

**Consequências:** é atrito e rastreabilidade, não barreira: comandos como `node -e` ainda contornam a restrição.

### 40. Shell supervisionado

**Status:** descartada

**Contexto:** uma alternativa ao prompt próprio seria abrir um shell comum e supervisionar o que o dev digita.

**Decisão:** descartado em favor do prompt próprio (decisão 39).

**Consequências:** um shell comum expande variáveis e permite pipes e redirecionamentos, o que torna a supervisão fácil de contornar. O prompt próprio executa comandos sem shell.

### 41. Painel web

**Status:** descartada (fora do escopo)

**Contexto:** ferramentas como o Infisical oferecem painel web, mas isso exige frontend, sessões no navegador e uma superfície de ataque maior.

**Decisão:** não há painel web. O modo interativo do CLI (decisão 37) cumpre esse papel.

**Consequências:** toda a operação acontece no terminal, coerente com o público-alvo (equipes de desenvolvimento) e com a proposta de simplicidade.

## Em aberto

Discutir antes de implementar a fatia correspondente.

- **10. A Fatia 6 (credenciais dinâmicas para PostgreSQL, com usuário temporário e `VALID UNTIL`) entra no TCC I?**
- **11. O `DELETE` de segredo apaga de vez ou só marca como removido? As versões antigas são guardadas para sempre?** Enquanto não for decidida, a decisão 30 impede apagar projeto com segredos.
