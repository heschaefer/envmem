# envmem

Gerenciador de segredos auto-hospedado para equipes de desenvolvimento. Os segredos (senhas de banco, chaves de API) ficam cifrados num servidor central, com controle de acesso por projeto e auditoria. O CLI busca os segredos e os entrega à aplicação direto em memória, como variáveis de ambiente, sem gravar nada em disco.

Trabalho de Conclusão de Curso de Sistemas de Informação (UNIMATER).
Autor: Henryque Schaefer. Orientador: Prof. Dr. Rafael Rodrigues Barbosa.

## Como funciona

```sh
envmem run --projeto app-homo -- node server.js
```

O CLI busca os segredos do projeto, monta o ambiente e chama `syscall.Exec`: o processo do CLI é substituído pela aplicação (mesmo PID), que recebe os segredos como variáveis de ambiente. A aplicação não precisa de nenhum código especial.

No servidor, cada segredo é cifrado com AES-256-GCM e uma chave de dados própria, que por sua vez é cifrada pela chave-mestra (envelope encryption). O servidor sobe selado e só decifra depois do unseal; a chave-mestra fica apenas em memória.

Também fazem parte do sistema: RBAC por projeto (superadmin, admin, gestor e desenvolvedor), MFA (TOTP) para os papéis administrativos, auditoria só com inserção e TLS 1.3 entre CLI e servidor. Sem argumentos, `envmem` abre um modo interativo com menus.

## Desenvolvimento

O ambiente roda num dev container (Go 1.26 e PostgreSQL 18, ver `.devcontainer/` e `docker-compose.yml`). Dentro dele:

```sh
make certs             # CA própria e certificado do servidor
make migrate           # aplica as migrações com o usuário dono do banco
make build             # gera bin/envmem e bin/envmem-server
make run-server
make test              # testes unitários
make test-integration  # testes com o PostgreSQL do compose
make check             # gofmt, go vet e govulncheck
```

As decisões de projeto estão em `docs/decisoes.md` e os roteiros de demonstração em `docs/evidencias/`. Só Linux e macOS.

## Uso de IA

O código deste repositório foi escrito com o apoio do Claude Code (Anthropic), um assistente de programação baseado em IA. As decisões de arquitetura e de segurança foram tomadas pelo autor, que revisou todo o código gerado.
