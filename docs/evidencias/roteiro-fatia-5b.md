# Roteiro da demonstração: Fatia 5b (modo interativo)

`envmem` sem argumentos abre menus navegáveis pelas setas (huh v2, decisões 37 e 49). É só uma camada: cada opção chama as mesmas funções dos subcomandos, que chamam as mesmas rotas da API. O menu esconde o que o papel não permite, mas quem decide é o servidor.

Tudo roda no terminal do dev container. A preparação é a da Fatia 5 (`docs/evidencias/roteiro-fatia-5.md`): servidor no ar e destravado, superadmin logado, projetos `demo` e `app-prod`, variáveis `DB_PASSWORD` e `API_KEY` no `demo`, e o usuário `dev@empresa.com` (senha temporária) como desenvolvedor do `demo`.

## 1. Desenvolvedor, primeiro uso

Num terminal com outro `~/.config` (como numa máquina nova, sem `config.json` nem token):

```sh
export XDG_CONFIG_HOME=$(mktemp -d)
./bin/envmem
```

Esperado:

- **Login pelo menu:** o formulário pede o endereço do servidor e o caminho do `ca.crt` (conferidos na hora: `http://` e arquivo inexistente são recusados), depois e-mail e senha, mascarada. Como a senha é temporária, pede a nova duas vezes (decisão 43). O `config.json` e o token são gravados como no `envmem login`.
- **Menu do desenvolvedor:** só o `demo` aparece (o `app-prod` não, decisão 6), e só com "Rodar um comando" e "Ver variáveis disponíveis (só nomes)".
- **Rodar um comando:** `echo $DB_PASSWORD` é recusado, porque o comando roda sem shell. Com `sh -c '...'`, o processo do menu vira a aplicação: o PID impresso pela aplicação é o do `envmem`, e a variável `ENVMEM_*` do ambiente não chega a ela.

## 2. Superadmin

No terminal do superadmin, `./bin/envmem`. Esperado:

- **Menu principal:** os projetos e, abaixo, "Criar projeto", "Remover projeto" e "Usuários".
- **Menu do projeto:** todas as ações. "Gravar uma variável" com uma variável nova confirma antes e pede o valor duas vezes, mascarado. "Ver o valor" mostra o valor, e a leitura vai para a auditoria. Em "Membros do projeto", o dev vira gestor.
- **Criar projeto:** o projeto nasce sem gestor (decisão 44).

## 3. O mesmo dev, agora gestor

De volta ao terminal do dev, `./bin/envmem`. Esperado:

- **Menu do gestor:** além das ações do desenvolvedor, ver o valor, gravar, lixeira e membros.
- **Lixeira:** só "Restaurar"; excluir de vez é de admin e superadmin (decisão 11).
- **Membros:** o gestor só adiciona desenvolvedores e não mexe em outro gestor.

## Saída registrada (23/10/2026, banco temporário, porta 8099)

Executada com um pseudoterminal (o módulo `pty` do Python) e `TERM=dumb`, que põe o huh no modo acessível: as mesmas telas em texto corrido, com as opções numeradas, o que torna a saída legível neste documento. No uso normal, as opções são escolhidas com as setas. Nesse modo, alguns textos fixos da biblioteca ficam em inglês ("Enter a number", `[y/N]`). As senhas e os valores digitados nos campos mascarados não aparecem na tela.

```
### 1. desenvolvedor, primeiro uso (PID do processo envmem iniciado: 407756; saiu com 0)
$ envmem
Endereço do servidor https://localhost:8099

Certificado da CA (caminho do ca.crt) certs/ca.crt

E-mail dev@empresa.com

Senha

Nova senha

Repita a nova senha

senha trocada.
sessão iniciada; válida até 24/10 03:13
envmem: dev@empresa.com
1. demo (desenvolvedor)
2. Sair
Enter a number between 1 and 2: 1

demo (desenvolvedor)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Voltar
Enter a number between 1 and 3: 2

API_KEY      v1  23/10/2026 19:13
DB_PASSWORD  v1  23/10/2026 19:13
demo (desenvolvedor)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Voltar
Enter a number between 1 and 3: 1

Comando echo $DB_PASSWORD
'$' não funciona aqui: o comando roda sem shell (sem pipes, redirecionamentos nem variáveis); ponha entre aspas para passar o caractere ao programa
Comando sh -c 'echo PID=$$ DB_PASSWORD com ${#DB_PASSWORD} caracteres, ENVMEM_SEGREDO_TESTE=[$ENVMEM_SEGREDO_TESTE]'

PID=407756 DB_PASSWORD com 14 caracteres, ENVMEM_SEGREDO_TESTE=[]

### 2. superadmin (saiu com 0)
$ envmem
envmem: admin@empresa.com (superadmin)
1. app-prod (superadmin)
2. demo (superadmin)
3. Criar projeto
4. Remover projeto
5. Usuários
6. Sair
Enter a number between 1 and 6: 2

demo (superadmin)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Ver o valor de uma variável
4. Gravar uma variável
5. Mandar uma variável para a lixeira
6. Ver a lixeira (restaurar ou excluir de vez)
7. Membros do projeto
8. Voltar
Enter a number between 1 and 8: 4

Gravar qual variável?
1. API_KEY (v1)
2. DB_PASSWORD (v1)
3. Nova variável
4. Voltar
Enter a number between 1 and 4: 3

Nome da variável REDIS_URL

A variável REDIS_URL não existe no projeto demo. Criar? [y/N] y

Valor

Repita o valor

REDIS_URL gravada no projeto demo (versão 1)
demo (superadmin)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Ver o valor de uma variável
4. Gravar uma variável
5. Mandar uma variável para a lixeira
6. Ver a lixeira (restaurar ou excluir de vez)
7. Membros do projeto
8. Voltar
Enter a number between 1 and 8: 3

Ver o valor de qual variável?
1. API_KEY (v1)
2. DB_PASSWORD (v1)
3. REDIS_URL (v1)
4. Voltar
Enter a number between 1 and 4: 3

REDIS_URL (versão 1):
redis://cache:6379/0
demo (superadmin)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Ver o valor de uma variável
4. Gravar uma variável
5. Mandar uma variável para a lixeira
6. Ver a lixeira (restaurar ou excluir de vez)
7. Membros do projeto
8. Voltar
Enter a number between 1 and 8: 5

Mandar qual variável para a lixeira?
1. API_KEY (v1)
2. DB_PASSWORD (v1)
3. REDIS_URL (v1)
4. Voltar
Enter a number between 1 and 4: 1

API_KEY foi para a lixeira do projeto demo
demo (superadmin)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Ver o valor de uma variável
4. Gravar uma variável
5. Mandar uma variável para a lixeira
6. Ver a lixeira (restaurar ou excluir de vez)
7. Membros do projeto
8. Voltar
Enter a number between 1 and 8: 7

Membros de demo
1. dev@empresa.com (desenvolvedor)
2. Adicionar membro
3. Voltar
Enter a number between 1 and 3: 1

dev@empresa.com (desenvolvedor)
1. Tornar gestor
2. Remover do projeto
3. Voltar
Enter a number between 1 and 3: 1

dev@empresa.com é gestor no projeto demo
Membros de demo
1. dev@empresa.com (gestor)
2. Adicionar membro
3. Voltar
Enter a number between 1 and 3: 3

demo (superadmin)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Ver o valor de uma variável
4. Gravar uma variável
5. Mandar uma variável para a lixeira
6. Ver a lixeira (restaurar ou excluir de vez)
7. Membros do projeto
8. Voltar
Enter a number between 1 and 8: 8

envmem: admin@empresa.com (superadmin)
1. app-prod (superadmin)
2. demo (superadmin)
3. Criar projeto
4. Remover projeto
5. Usuários
6. Sair
Enter a number between 1 and 6: 3

Nome do projeto app-homo

projeto app-homo criado; nomeie um gestor em Membros do projeto
envmem: admin@empresa.com (superadmin)
1. app-homo (superadmin)
2. app-prod (superadmin)
3. demo (superadmin)
4. Criar projeto
5. Remover projeto
6. Usuários
7. Sair
Enter a number between 1 and 7: 7

### 3. o mesmo dev, agora gestor (saiu com 0)
$ envmem
envmem: dev@empresa.com
1. demo (gestor)
2. Sair
Enter a number between 1 and 2: 1

demo (gestor)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Ver o valor de uma variável
4. Gravar uma variável
5. Mandar uma variável para a lixeira
6. Ver a lixeira (restaurar)
7. Membros do projeto
8. Voltar
Enter a number between 1 and 8: 6

Lixeira de demo
1. API_KEY (v1, removida em 23/10/2026 19:13)
2. Voltar
Enter a number between 1 and 2: 1

API_KEY
1. Restaurar
2. Voltar
Enter a number between 1 and 2: 1

API_KEY restaurada no projeto demo
demo (gestor)
1. Rodar um comando
2. Ver variáveis disponíveis (só nomes)
3. Ver o valor de uma variável
4. Gravar uma variável
5. Mandar uma variável para a lixeira
6. Ver a lixeira (restaurar)
7. Membros do projeto
8. Voltar
Enter a number between 1 and 8: 8

envmem: dev@empresa.com
1. demo (gestor)
2. Sair
Enter a number between 1 and 2: 2
```

Nessa execução, nem os valores nem as senhas aparecem no log do servidor. O mesmo fluxo de menus também foi conferido no modo normal, com as setas: navegação, login com a senha mascarada (`****`) e Ctrl+C para sair. A navegação pelos menus não tem teste automático; as regras do que cada papel vê (`projectActions`, `memberActions` e `globalActions`) e o separador de argumentos (`splitCommand`) têm testes unitários (`make test`).
