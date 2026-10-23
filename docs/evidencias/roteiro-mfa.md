# Roteiro da demonstração: MFA

O MFA (decisões 36 e 50) é exigido no login de superadmin, admin e gestor. O código é o TOTP de 6 dígitos dos apps autenticadores, calculado pelo próprio envmem (RFC 6238, só com a biblioteca padrão). O login vira duas etapas: a senha certa rende um desafio curto, e o código troca o desafio pela sessão.

Tudo roda no terminal do dev container, com o servidor no ar e o superadmin logado (preparação da Fatia 5). Antes, rode `make migrate` (migrações 00006 e 00007). Desde o MFA, **o superadmin só entra com o cofre aberto**: o segredo do TOTP é cifrado pelo cofre, então o unseal vem antes do login. Numa instalação nova, a ordem é `keygen`, `create-superadmin`, subir o servidor, unseal e o primeiro login, que cadastra o MFA.

Para conferir os códigos, use um app autenticador no celular (Google Authenticator, Authy, FreeOTP...).

## Passos

1. **Usuária nova:** o superadmin cria a admin `ana@empresa.com` (`envmem users create --papel admin`).
2. **Primeiro login da ana:** depois da senha temporária, o CLI mostra o QR code (e a chave em texto); ela escaneia com o app, digita o código (um código errado pede outro) e troca a senha temporária.
3. **Login seguinte:** senha e o código atual do app.
4. **Exclusão definitiva:** `envmem secrets purge` pede o código de novo (decisão 11). Cada código vale uma vez: logo depois do login, espere o app mostrar o próximo.
5. **Senha vazada:** alguém com a senha da ana, de outro computador, tenta adivinhar o código. Na décima tentativa errada seguida, o MFA da conta trava.
6. **Trava:** nem a ana, com a senha e o código certos, entra.
7. **Reset:** o superadmin reseta o MFA da ana (`envmem users reset-mfa`); as sessões dela caem, e o próximo login pede um cadastro novo, com outra chave.
8. **Auditoria:** cada etapa fica registrada, com o IP de origem e sem nenhum código nem segredo.

## Saída registrada (23/10/2026, banco temporário, porta 8099)

Executada com um pseudoterminal (o módulo `pty` do Python); os códigos foram calculados a partir da chave mostrada na tela, por uma implementação independente (HMAC-SHA1 do Python), como um app autenticador faria. O QR code aparece aqui sem as cores, que no terminal forçam preto sobre branco; a chave foi trocada por `<CHAVE>`. O QR é de uma conta de teste, num banco temporário já apagado. Para separar a ana do "atacante", ela entra por `127.0.0.1` e ele por `::1` (o `localhost` resolve para `::1`, e o limite de tentativas também conta por IP, decisão 45).

### 1. O superadmin cria a admin ana (senha temporária)
```
$ printf 'temporaria-da-ana\n' | envmem users create --senha-stdin --papel admin ana@empresa.com
usuário ana@empresa.com criado com senha temporária, válida por 72 horas e trocada no primeiro envmem login
```

### 2. Primeiro login da ana: cadastro do MFA com QR code
```
$ envmem login --servidor https://127.0.0.1:8099 ana@empresa.com
Senha:
O MFA é obrigatório para o seu papel. Cadastre o envmem no app autenticador
(Google Authenticator, Authy, FreeOTP...).



    █▀▀▀▀▀█   ▄▀▀▀▄█  ▄▄▄▄▀█▄ ▄█▄ ██  █▀▀▀▀▀█
    █ ███ █ ▀▀ ▄ ██▄  ▀ ▄▄▄▀▄▄▄   ██  █ ███ █
    █ ▀▀▀ █   ▄▄▄ ▀▄▀  ▄ ▄▀▄ ▄▀▄▄█▄█▀ █ ▀▀▀ █
    ▀▀▀▀▀▀▀ █ █ ▀▄█ █▄█ █▄█ █▄▀▄▀▄█▄▀ ▀▀▀▀▀▀▀
    ███ ██▀█▀▄▀█▄██ ▄▄   ▀   █▄▀██  ▄▀█  ▄▀▄▄
    ▀█▄▀▄▀▀▄▄▄▀ ▄▄█▄ █▄▄▄▄ ▄▄█ ▄▄██ █▀▀▀▄ ▀▀▀
    ▄▀▀▄█▀▀██▄ ██ ███  ▀  ▄█▄▄▄▄██ ▀ ▀█   ▄▀█
     ▄▀▀█ ▀▀▀▄ ▀█▄▄ ▀▄▀ ▀▄   █▀ ▄▄▄  █▀▄▀  █▀
    ▀ ▄▀ █▀▀  ▀▀█▀█ █  ▀██ ▀██  ██  ███▄ █ ██
    ▀ ▄▀ ▀▀ ▄▄█▄▄▀  ▄█ ▄▀▄  ▄▄▄▄▀▄▄▄▄▄█▀▄▀▀▀▀
    █▀▀▄ █▀ █▄▀▄ ▄   ▄ ██▄ ██▄▄▄█▀   ██▀ ▀ ▀▄
    ▀ ▄▄▀█▀  ▀█▄ █ ▄ ▄█▄ █▄▄▄▄▄▄▄▄▄▄▄▀▄    ▀█
    ▀▄▀   ▀ ▀█  ▄█▀▀█▀█▀█▀  ██▄████▀█▀█▄   ▀▄
     ▄██▄█▀▀▀█▀  ▄█▄ ▄█▄█▄█  ▄█▄ ██ ▄  ▄▄▀▀▄█
     ▀ ▀██▀█▄▄▀▄█▄██▄▄▄▄█  ▄▄▄   ▀▄▀ ██▄ ▀▄▄█
    ▀▄  ▀ ▀ ▀▀▄▀██ ▄ ▄█  █▄  ██▄██▀▄██▀▀█▀▀▀▀
    ▀ ▀▀ ▀▀▀▄██▀▄▀  █▀▀▀▄█▄ ██  ██ ▄█▀▀▀█  ▀▄
    █▀▀▀▀▀█ █ ▄  ▀ ▄█▄▀▄ █▀ ███ ██▀██ ▀ █ ▀▀▀
    █ ███ █ ▀▀▀▄   ▄▄▄▄██▄ ▀ ▄ ▀▄█ ▄▀▀▀▀█  ▀█
    █ ▀▀▀ █ ███▄ ▄█ ▄█  ▀█▀ ▄▄█▄▄▄█▄█▀▄▄▀▀▀█▀
    ▀▀▀▀▀▀▀ ▀ ▀  ▀  ▀▀ ▀▀▀  ▀▀▀ ▀▀ ▀▀▀     ▀▀



Escaneie o QR code acima ou digite esta chave no app:

    <CHAVE EM GRUPOS DE 4>

ou abra este link:
otpauth://totp/envmem:ana@empresa.com?algorithm=SHA1&digits=6&issuer=envmem&period=30&secret=<CHAVE>

A chave só aparece agora; não a guarde em outro lugar.
Código do app autenticador (6 dígitos): 000000
código incorreto; tente de novo com o código atual do app
Código do app autenticador (6 dígitos): 024182
Sua senha é temporária. Escolha uma senha nova.
Nova senha (de 12 a 128 caracteres):
Repita a nova senha:
senha trocada.
sessão iniciada; válida até 24/10 04:28
```

### 3. Login seguinte: senha e código
```
$ envmem login --servidor https://127.0.0.1:8099 ana@empresa.com
Senha:
Código do app autenticador (6 dígitos): 717885
sessão iniciada; válida até 24/10 04:29
```

### 4. Exclusão definitiva: o código é pedido de novo
```
$ envmem secrets rm --projeto demo API_KEY
API_KEY foi para a lixeira do projeto demo (desfaça com envmem secrets restore)

$ envmem secrets purge --projeto demo API_KEY
Código do app autenticador (6 dígitos): 596748
API_KEY excluída definitivamente do projeto demo
```

### 5. Alguém com a senha da ana, de outro IP (::1), tenta adivinhar o código
```
tentativa  1: invalid_mfa_code
tentativa  2: invalid_mfa_code
tentativa  3: invalid_mfa_code
tentativa  4: invalid_mfa_code
tentativa  5: invalid_mfa_code
tentativa  6: invalid_mfa_code
tentativa  7: invalid_mfa_code
tentativa  8: invalid_mfa_code
tentativa  9: invalid_mfa_code
tentativa 10: mfa_locked
```

### 6. A ana, com a senha e o código certos: o MFA está travado
```
$ envmem login --servidor https://127.0.0.1:8099 ana@empresa.com
Senha:
envmem: servidor respondeu 403 (mfa_locked): o MFA desta conta travou por excesso de códigos errados; peça o reset a um superadmin
```

### 7. O superadmin reseta o MFA da ana; ela cadastra de novo
```
$ envmem users reset-mfa ana@empresa.com
MFA de ana@empresa.com resetado: o app é cadastrado de novo no próximo login, e as sessões abertas foram encerradas

$ envmem login ana@empresa.com
Senha:
(QR code e chave novos; a chave antiga não vale mais: True)
```

### 8. Auditoria da ana (resumida)
```
user.create        success  ::1             admin@empresa.com
auth.mfa_challenge success  127.0.0.1       ana@empresa.com
auth.mfa           failure  127.0.0.1       ana@empresa.com
auth.login         success  127.0.0.1       ana@empresa.com
mfa.enroll         success  127.0.0.1       ana@empresa.com
auth.password_change success  127.0.0.1       ana@empresa.com
auth.mfa_challenge success  127.0.0.1       ana@empresa.com
auth.login         success  127.0.0.1       ana@empresa.com
secret.purge       success  127.0.0.1       ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
auth.mfa_challenge success  ::1             ana@empresa.com
auth.mfa           failure  ::1             ana@empresa.com
mfa.locked         success  ::1             ana@empresa.com
auth.mfa           denied   127.0.0.1       ana@empresa.com
mfa.reset          success  ::1             admin@empresa.com
auth.mfa_challenge success  127.0.0.1       ana@empresa.com
```
segredo do TOTP no JSON da auditoria: False

Nessa execução, nem as senhas nem os valores aparecem no log do servidor. O mesmo fluxo pela API (cadastro, login, reuso do código, limites do desafio, trava, reset, cofre selado e exclusão definitiva) roda automaticamente nos testes de `internal/api` (`make test`), e o `TestEndToEnd` (`make test-integration`) cobre o login com MFA pelo pipe no banco real.
