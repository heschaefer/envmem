package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/heschaefer/envmem/internal/client"
)

// MFA no login (decisão 36). Para superadmin, admin e gestor, a senha
// certa rende um desafio, e não a sessão: o CLI cadastra o app
// autenticador (no primeiro login) e pede o código, que troca o desafio
// pela sessão. completeMFA é o fluxo, comum ao subcomando login e ao modo
// interativo; mfaUI é só como cada um mostra e pergunta.

// mfaUI mostra o cadastro e pede o código.
type mfaUI interface {
	// showSetup mostra a chave e o link do cadastro (e o QR code).
	showSetup(setup client.MFASetup) error
	// code pede o código de 6 dígitos do app.
	code() (string, error)
	// retry diz se, depois de um código errado, dá para pedir outro (no
	// terminal e no menu, sim; lendo do stdin, não).
	retry() bool
}

// completeMFA completa o login de quem precisa de MFA e devolve o resultado
// com a sessão. Sem MFA (res.MFA vazio), devolve res como veio.
func completeMFA(c *client.Client, res client.LoginResult, ui mfaUI) (client.LoginResult, error) {
	if res.MFA == "" {
		return res, nil
	}
	if res.MFA == "setup" {
		ctx, cancel := apiContext()
		setup, err := c.MFASetup(ctx, res.Challenge)
		cancel()
		if err != nil {
			return client.LoginResult{}, err
		}
		if err := ui.showSetup(setup); err != nil {
			return client.LoginResult{}, err
		}
	}
	for {
		code, err := ui.code()
		if err != nil {
			return client.LoginResult{}, err
		}
		// O prazo começa depois da digitação (ver apiContext).
		ctx, cancel := apiContext()
		got, err := c.MFAVerify(ctx, res.Challenge, strings.TrimSpace(code))
		cancel()
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "invalid_mfa_code" && ui.retry() {
			fmt.Fprintln(os.Stderr, "código incorreto; tente de novo com o código atual do app")
			continue
		}
		return got, err
	}
}

// terminalMFA é o MFA do subcomando login: no terminal, ou, com
// --senha-stdin, o código na linha seguinte à da senha.
type terminalMFA struct{ fromStdin bool }

func (t terminalMFA) showSetup(setup client.MFASetup) error {
	// O cadastro precisa de uma pessoa com o app na mão.
	if t.fromStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("o MFA é obrigatório para o seu papel e ainda não foi cadastrado; rode envmem login num terminal")
	}
	fmt.Fprint(os.Stderr, setupInstructions(setup))
	return nil
}

func (t terminalMFA) code() (string, error) {
	if !t.fromStdin {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", errors.New("o MFA pede o código do app; rode envmem login num terminal, ou passe o código na linha depois da senha com --senha-stdin")
		}
		fmt.Fprint(os.Stderr, "Código do app autenticador (6 dígitos): ")
	}
	// O código aparece na tela: vale uma vez só e por segundos, então não
	// há o que esconder, e ver o que foi digitado evita erros.
	line, err := readLine(os.Stdin)
	return string(line), err
}

func (t terminalMFA) retry() bool { return !t.fromStdin }

// setupInstructions é o texto do cadastro: a chave em grupos de 4 (mais
// fácil de digitar) e o link. O segredo aparece uma única vez, aqui; quem
// tiver a chave gera os códigos, então ela não deve ser copiada para
// nenhum outro lugar.
func setupInstructions(setup client.MFASetup) string {
	var groups []string
	for s := setup.Secret; len(s) > 0; {
		n := min(4, len(s))
		groups = append(groups, s[:n])
		s = s[n:]
	}
	return "O MFA é obrigatório para o seu papel. Cadastre o envmem no app autenticador\n" +
		"(Google Authenticator, Authy, FreeOTP...), digitando esta chave:\n\n" +
		"    " + strings.Join(groups, " ") + "\n\n" +
		"ou abrindo este link:\n" + setup.URI + "\n\n" +
		"A chave só aparece agora; não a guarde em outro lugar.\n"
}
