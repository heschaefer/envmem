package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	"charm.land/huh/v2"

	"github.com/heschaefer/envmem/internal/client"
)

// interactiveSession devolve um cliente com sessão válida e o dono dela.
// Se não houver token, ou se ele venceu ou foi revogado, abre o formulário
// de login, que grava o config.json e o token como o "envmem login".
func interactiveSession() (*client.Client, client.Me, error) {
	// Sem flags: servidor e CA vêm do config.json.
	conn := addConnFlags(flag.NewFlagSet("envmem", flag.ContinueOnError))
	cfg, err := conn.resolve()
	if err != nil {
		return nil, client.Me{}, err
	}

	c, err := conn.authedClient()
	if err == nil {
		ctx, cancel := apiContext()
		me, err := c.Me(ctx)
		cancel()
		if err == nil {
			return c, me, nil
		}
		if !isUnauthorized(err) {
			return nil, client.Me{}, err
		}
		fmt.Fprintln(os.Stderr, "a sessão venceu ou foi encerrada; entre de novo")
	} else if !errors.Is(err, errNoSession) {
		return nil, client.Me{}, err
	}

	// Sem config.json (primeiro uso), o formulário pede também o servidor e
	// o caminho do ca.crt que o time distribui.
	path, err := configPath()
	if err != nil {
		return nil, client.Me{}, err
	}
	_, statErr := os.Stat(path)
	askServer := errors.Is(statErr, fs.ErrNotExist)
	return loginForm(cfg, askServer)
}

// isUnauthorized diz se o servidor recusou o token (401): sessão vencida,
// revogada ou inexistente.
func isUnauthorized(err error) bool {
	var apiErr *client.APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized
}

// loginForm pede e-mail e senha (e, no primeiro uso, servidor e CA) até o
// login dar certo ou o usuário sair (Ctrl+C). Um erro (senha errada, 429
// do limite de tentativas, servidor fora do ar) é mostrado e o formulário
// volta, com o que já foi digitado, exceto a senha.
func loginForm(cfg cliConfig, askServer bool) (*client.Client, client.Me, error) {
	// No primeiro uso, o campo do servidor começa vazio (com um exemplo
	// como dica), em vez do https://localhost:8080 padrão, que só serve
	// no ambiente de desenvolvimento.
	if askServer {
		cfg.Server = ""
	}
	var email string
	for {
		var password string
		var fields []huh.Field
		if askServer {
			fields = append(fields,
				huh.NewInput().
					Title("Endereço do servidor").
					Description("Passado pelo time").
					Placeholder("https://envmem.empresa.com:8443").
					Value(&cfg.Server).
					Validate(func(s string) error {
						// No modo acessível (TERM=dumb), o validador recebe o
						// texto digitado antes de o huh aplicar o valor atual:
						// Enter vazio numa nova tentativa mantém o endereço já
						// digitado. No modo com setas, o campo e cfg.Server são
						// a mesma variável, e apagar o texto continua recusado.
						if s == "" && cfg.Server != "" {
							return nil
						}
						_, err := client.New(s, nil)
						return err
					}),
				huh.NewInput().
					Title("Certificado da CA (caminho do ca.crt)").
					Description("Arquivo recebido do time; vazio usa as CAs do sistema").
					Value(&cfg.CA).
					Validate(func(s string) error {
						if s == "" {
							return nil
						}
						_, err := client.LoadCA(s)
						return err
					}),
			)
		}
		fields = append(fields,
			huh.NewInput().Title("E-mail").Value(&email),
			huh.NewInput().Title("Senha").EchoMode(huh.EchoModePassword).Value(&password),
		)
		if err := huh.NewForm(huh.NewGroup(fields...).Title("Entrar no envmem")).Run(); err != nil {
			return nil, client.Me{}, err
		}

		c, me, err := tryLogin(cfg, email, password)
		if err == nil {
			return c, me, nil
		}
		if isAbort(err) {
			return nil, client.Me{}, err
		}
		printError(err)
	}
}

// tryLogin faz o login e completa a sessão com o mesmo openSession do
// "envmem login": troca a senha temporária (num formulário) e grava o
// config.json e o token.
func tryLogin(cfg cliConfig, email, password string) (*client.Client, client.Me, error) {
	// O config.json é lido de qualquer pasta, então o caminho vira absoluto.
	if cfg.CA != "" {
		abs, err := filepath.Abs(cfg.CA)
		if err != nil {
			return nil, client.Me{}, err
		}
		cfg.CA = abs
	}
	c, err := newClient(cfg)
	if err != nil {
		return nil, client.Me{}, err
	}

	ctx, cancel := apiContext()
	res, err := c.Login(ctx, email, password)
	cancel()
	if err == nil {
		res, err = completeMFA(c, res, formMFA{})
	}
	if err != nil {
		return nil, client.Me{}, err
	}
	newPassword := func() (string, error) {
		return readTwiceForm("Nova senha", "Sua senha é temporária. Escolha uma nova, de 12 a 128 caracteres.",
			"Repita a nova senha", "as senhas não conferem")
	}
	if err := openSession(c, cfg, res, password, newPassword); err != nil {
		return nil, client.Me{}, err
	}

	ctx, cancel = apiContext()
	defer cancel()
	me, err := c.Me(ctx)
	return c, me, err
}

// formMFA é o MFA do modo interativo, em formulários do huh.
type formMFA struct{}

func (formMFA) showSetup(setup client.MFASetup) error {
	// As instruções vão direto para o terminal, antes do formulário do
	// código: no modo acessível (TERM=dumb), o huh não mostra descrições.
	// Não há um "já cadastrei?": o próprio código do app prova o cadastro.
	fmt.Fprint(os.Stderr, setupInstructions(setup))
	return nil
}

func (formMFA) code() (string, error) {
	var code string
	err := huh.NewInput().
		Title("Código do app autenticador").
		Description("6 dígitos; muda a cada 30 segundos. No primeiro login, cadastre o app antes.").
		Value(&code).
		Run()
	return code, err
}

func (formMFA) retry() bool { return true }
