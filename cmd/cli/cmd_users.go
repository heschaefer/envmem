package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/heschaefer/envmem/internal/client"
)

// cmdUsers implementa "envmem users list|create|rm|reset-password". Todas
// as ações são de superadmin, conferidas no servidor.
func cmdUsers(args []string) int {
	if len(args) == 0 {
		usersUsage(os.Stderr)
		return 2
	}
	action, args := args[0], args[1:]

	// list não tem argumento; as outras recebem o e-mail.
	var wantEmail bool
	switch action {
	case "list":
	case "create", "rm", "reset-password":
		wantEmail = true
	case "help", "-h", "-help", "--help":
		usersUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "envmem users: ação desconhecida %q\n\n", action)
		usersUsage(os.Stderr)
		return 2
	}

	fs := flag.NewFlagSet("users "+action, flag.ContinueOnError)
	conn := addConnFlags(fs)
	var papel string
	var fromStdin, sim bool
	switch action {
	case "create":
		fs.StringVar(&papel, "papel", "", `papel global: "admin" ou "superadmin"; vazio para usuário comum`)
		fallthrough
	case "reset-password":
		fs.BoolVar(&fromStdin, "senha-stdin", false, "lê a senha temporária de uma linha do stdin, em vez de pedir no terminal")
	case "rm":
		fs.BoolVar(&sim, "sim", false, "remove sem pedir confirmação (para scripts)")
	}
	fs.Usage = func() {
		if wantEmail {
			fmt.Fprintf(fs.Output(), "Uso: envmem users %s [opções] EMAIL\n", action)
		} else {
			fmt.Fprintf(fs.Output(), "Uso: envmem users %s [opções]\n", action)
		}
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if (wantEmail && fs.NArg() != 1) || (!wantEmail && fs.NArg() != 0) {
		fs.Usage()
		return 2
	}
	email := fs.Arg(0)

	c, err := conn.authedClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 2
	}
	// create e reset-password esperam o usuário digitar: o prazo é maior.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	switch action {
	case "list":
		err = usersList(ctx, c, os.Stdout)
	case "create":
		err = usersCreate(ctx, c, email, papel, fromStdin)
	case "rm":
		err = usersRemove(ctx, c, email, sim)
	case "reset-password":
		err = usersResetPassword(ctx, c, email, fromStdin)
	}
	if errors.Is(err, errCanceled) {
		fmt.Fprintln(os.Stderr, "cancelado")
		return 1
	}
	if err != nil {
		printError(err)
		return 1
	}
	return 0
}

// usersList imprime um usuário por linha: e-mail, papel global e se a
// senha ainda é temporária.
func usersList(ctx context.Context, c *client.Client, w io.Writer) error {
	users, err := c.Users(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, u := range users {
		role := u.GlobalRole
		if role == "" {
			role = "usuário"
		}
		// A terceira coluna só existe quando há o que mostrar: assim a
		// linha não termina com espaços.
		fmt.Fprintf(tw, "%s\t%s", u.Email, role)
		if u.TempPassword {
			fmt.Fprint(tw, "\tsenha temporária")
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

// usersCreate cria o usuário com uma senha temporária digitada por quem
// cria (decisão 43). Quem recebe a conta troca a senha no primeiro login,
// então o superadmin não conhece a senha definitiva de ninguém.
func usersCreate(ctx context.Context, c *client.Client, email, role string, fromStdin bool) error {
	password, err := readTempPassword(fromStdin)
	defer clear(password)
	if err != nil {
		return err
	}
	return createUser(ctx, c, email, role, string(password))
}

// createUser cria o usuário e mostra o resultado. É a parte comum ao
// subcomando e ao modo interativo, que só muda de onde vem a senha.
func createUser(ctx context.Context, c *client.Client, email, role, password string) error {
	u, err := c.CreateUser(ctx, email, role, password)
	if err != nil {
		return err
	}
	fmt.Printf("usuário %s criado com senha temporária, válida por 72 horas e trocada no primeiro envmem login\n", u.Email)
	return nil
}

// usersRemove remove um usuário. As sessões e os vínculos com projetos vão
// junto (no banco, ON DELETE CASCADE) e não há lixeira: por isso pede
// confirmação no terminal e, em scripts, exige --sim. A auditoria guarda
// cópia do e-mail, então os eventos antigos continuam legíveis.
func usersRemove(ctx context.Context, c *client.Client, email string, yes bool) error {
	u, err := findUser(ctx, c, email)
	if err != nil {
		return err
	}
	if !yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("o stdin não é um terminal; use --sim para remover sem confirmação")
		}
		ok, err := confirm(fmt.Sprintf("Remover %s? As sessões e os acessos a projetos são apagados, sem como desfazer.", u.Email))
		if err != nil {
			return err
		}
		if !ok {
			return errCanceled
		}
	}
	return deleteUser(ctx, c, u)
}

// deleteUser remove o usuário (pelo id) e mostra o resultado.
func deleteUser(ctx context.Context, c *client.Client, u client.User) error {
	if err := c.DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	fmt.Printf("usuário %s removido\n", u.Email)
	return nil
}

// usersResetPassword define uma nova senha temporária para quem esqueceu a
// senha (decisão 46). O servidor revoga as sessões do usuário.
func usersResetPassword(ctx context.Context, c *client.Client, email string, fromStdin bool) error {
	u, err := findUser(ctx, c, email)
	if err != nil {
		return err
	}
	password, err := readTempPassword(fromStdin)
	defer clear(password)
	if err != nil {
		return err
	}
	return resetPassword(ctx, c, u, string(password))
}

// resetPassword define a senha temporária (pelo id) e mostra o resultado.
func resetPassword(ctx context.Context, c *client.Client, u client.User, password string) error {
	if err := c.ResetPassword(ctx, u.ID, password); err != nil {
		return err
	}
	fmt.Printf("senha de %s redefinida: a nova é temporária (72 horas), e as sessões abertas foram encerradas\n", u.Email)
	return nil
}

// findUser acha o usuário pelo e-mail. As rotas recebem o id, porque o
// caminho vai para o log do servidor e o e-mail não deve ir.
func findUser(ctx context.Context, c *client.Client, email string) (client.User, error) {
	users, err := c.Users(ctx)
	if err != nil {
		return client.User{}, err
	}
	// O servidor guarda o e-mail em minúsculas.
	email = strings.ToLower(strings.TrimSpace(email))
	for _, u := range users {
		if u.Email == email {
			return u, nil
		}
	}
	return client.User{}, fmt.Errorf("usuário %s não encontrado", email)
}

// readTempPassword lê a senha temporária: no terminal, duas vezes e sem
// eco; com fromStdin, uma linha do stdin. Nunca por argumento.
func readTempPassword(fromStdin bool) ([]byte, error) {
	if fromStdin {
		return readPassword("", true)
	}
	return readTwice("Senha temporária (de 12 a 128 caracteres): ", "Repita a senha temporária: ", "as senhas não conferem")
}

func usersUsage(w io.Writer) {
	fmt.Fprint(w, `Uso: envmem users <ação> [opções] [EMAIL]

Ações (só superadmin):
  list                   lista os usuários, com o papel global
  create EMAIL           cria um usuário com senha temporária
                         (--papel admin ou --papel superadmin para papel global)
  rm EMAIL               remove um usuário (pede confirmação; --sim em scripts)
  reset-password EMAIL   define uma nova senha temporária e encerra as sessões

A senha temporária é digitada por quem cria, vale 72 horas e é trocada pelo
usuário no primeiro envmem login. Gestor e desenvolvedor são papéis por
projeto: veja envmem members.
`)
}
