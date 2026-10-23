package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/heschaefer/envmem/internal/client"
	"github.com/heschaefer/envmem/internal/envname"
)

// errCanceled indica que o usuário respondeu não a uma confirmação.
var errCanceled = errors.New("cancelado")

// cmdSecrets implementa "envmem secrets list|get|set|rm|restore|trash|purge".
// O CLI não decide quem pode o quê: cada ação é conferida no servidor
// (RBAC), e o CLI só mostra a resposta.
func cmdSecrets(args []string) int {
	if len(args) == 0 {
		secretsUsage(os.Stderr)
		return 2
	}
	action, args := args[0], args[1:]

	// list e trash não têm argumento; as outras recebem o nome da variável.
	var wantKey bool
	switch action {
	case "list", "trash":
	case "get", "set", "rm", "restore", "purge":
		wantKey = true
	case "help", "-h", "-help", "--help":
		secretsUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "envmem secrets: ação desconhecida %q\n\n", action)
		secretsUsage(os.Stderr)
		return 2
	}

	fs := flag.NewFlagSet("secrets "+action, flag.ContinueOnError)
	projeto := fs.String("projeto", "", "projeto das variáveis")
	conn := addConnFlags(fs)
	var versao int
	var fromStdin, criar bool
	switch action {
	case "get":
		fs.IntVar(&versao, "versao", 0, "versão a ler (padrão: a atual)")
	case "set":
		fs.BoolVar(&fromStdin, "valor-stdin", false, "lê o valor do stdin, em vez de pedir no terminal")
		fs.BoolVar(&criar, "criar", false, "com --valor-stdin, permite criar uma variável que ainda não existe")
	}
	fs.Usage = func() {
		switch {
		case action == "list":
			fmt.Fprintln(fs.Output(), "Uso: envmem secrets list [--projeto X] [opções]")
		case wantKey:
			fmt.Fprintf(fs.Output(), "Uso: envmem secrets %s --projeto X [opções] NOME\n", action)
		default:
			fmt.Fprintf(fs.Output(), "Uso: envmem secrets %s --projeto X [opções]\n", action)
		}
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// Só o list funciona sem projeto: aí percorre todos os do usuário.
	if (wantKey && fs.NArg() != 1) || (!wantKey && fs.NArg() != 0) || (*projeto == "" && action != "list") {
		fs.Usage()
		return 2
	}
	key := fs.Arg(0)

	c, err := conn.authedClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envmem: %v\n", err)
		return 2
	}
	// O set pode esperar o usuário digitar: o prazo é maior.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	switch action {
	case "list":
		err = secretsList(ctx, c, *projeto, os.Stdout)
	case "get":
		var s client.SecretVersion
		if s, err = c.Secret(ctx, *projeto, key, versao); err == nil {
			fmt.Println(s.Value)
		}
	case "set":
		err = secretsSet(ctx, c, *projeto, key, fromStdin, criar)
	case "rm":
		if err = c.TrashSecret(ctx, *projeto, key); err == nil {
			fmt.Printf("%s foi para a lixeira do projeto %s (desfaça com envmem secrets restore)\n", key, *projeto)
		}
	case "restore":
		if err = c.RestoreSecret(ctx, *projeto, key); err == nil {
			fmt.Printf("%s restaurada no projeto %s\n", key, *projeto)
		}
	case "trash":
		err = secretsTrash(ctx, c, *projeto, os.Stdout)
	case "purge":
		if err = c.PurgeSecret(ctx, *projeto, key); err == nil {
			fmt.Printf("%s excluída definitivamente do projeto %s\n", key, *projeto)
		}
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

// secretsList lista os nomes das variáveis, nunca os valores. Com projeto,
// uma variável por linha (para scripts). Sem projeto, percorre todos os
// projetos do usuário, com o papel em cada um, inclusive os que ainda não
// têm variáveis.
func secretsList(ctx context.Context, c *client.Client, project string, w io.Writer) error {
	if project != "" {
		metas, err := c.SecretsMeta(ctx, project)
		if err != nil {
			return err
		}
		return writeMetas(w, "", metas)
	}

	projects, err := c.Projects(ctx)
	if err != nil {
		return err
	}
	if len(projects) == 0 {
		fmt.Fprintln(os.Stderr, "você não tem acesso a nenhum projeto")
		return nil
	}
	for i, p := range projects {
		metas, err := c.SecretsMeta(ctx, p.Name)
		if err != nil {
			return fmt.Errorf("projeto %s: %w", p.Name, err)
		}
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s (%s)\n", p.Name, p.Role)
		if len(metas) == 0 {
			fmt.Fprintln(w, "  (sem variáveis)")
			continue
		}
		if err := writeMetas(w, "  ", metas); err != nil {
			return err
		}
	}
	return nil
}

// writeMetas imprime nome, versão atual e data da última gravação, em
// colunas alinhadas.
func writeMetas(w io.Writer, indent string, metas []client.SecretMeta) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, m := range metas {
		fmt.Fprintf(tw, "%s%s\tv%d\t%s\n", indent, m.Key, m.Version, m.UpdatedAt.Local().Format("02/01/2006 15:04"))
	}
	return tw.Flush()
}

// secretsTrash lista a lixeira do projeto.
func secretsTrash(ctx context.Context, c *client.Client, project string, w io.Writer) error {
	trashed, err := c.Trash(ctx, project)
	if err != nil {
		return err
	}
	if len(trashed) == 0 {
		fmt.Fprintln(os.Stderr, "a lixeira está vazia")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, t := range trashed {
		fmt.Fprintf(tw, "%s\tv%d\tremovida em %s\n", t.Key, t.Version, t.DeletedAt.Local().Format("02/01/2006 15:04"))
	}
	return tw.Flush()
}

// secretsSet grava uma nova versão de uma variável. Se ela ainda não
// existe (ou está na lixeira), pede confirmação antes, para que um nome
// digitado errado não crie uma variável nova em silêncio. Em scripts
// (--valor-stdin) não há como perguntar, e criar exige --criar.
//
// A confirmação é conforto, não controle de acesso: quem decide se a
// gravação é permitida é o servidor, no PUT.
func secretsSet(ctx context.Context, c *client.Client, project, key string, fromStdin, create bool) error {
	if !fromStdin && !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("o stdin não é um terminal; use --valor-stdin para ler o valor de um pipe")
	}
	state, err := secretState(ctx, c, project, key)
	if err != nil {
		return err
	}
	if question := state.question(project, key); question != "" {
		if fromStdin && !create {
			return fmt.Errorf("a variável %s não existe no projeto %s (ou está na lixeira); use --criar para gravá-la", key, project)
		}
		if !fromStdin {
			ok, err := confirm(question)
			if err != nil {
				return err
			}
			if !ok {
				return errCanceled
			}
		}
	}

	value, err := readSecretValue(fromStdin)
	defer clear(value)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return errors.New("o valor está vazio")
	}
	// A conversão para string (exigida pelo JSON) faz uma cópia que não dá
	// para zerar: em Go, strings são imutáveis. O mesmo vale para a senha
	// no login.
	return putSecret(ctx, c, project, key, string(value))
}

// putSecret grava a versão nova e mostra o número dela.
func putSecret(ctx context.Context, c *client.Client, project, key, value string) error {
	version, err := c.PutSecret(ctx, project, key, value)
	if err != nil {
		return err
	}
	fmt.Printf("%s gravada no projeto %s (versão %d)\n", key, project, version)
	return nil
}

// keyState diz se uma variável existe, está na lixeira ou é nova.
type keyState int

const (
	keyExists keyState = iota
	keyTrashed
	keyNew
)

// question é a confirmação a pedir antes de gravar, ou "" se a variável
// já existe e a gravação é só uma versão nova.
func (s keyState) question(project, key string) string {
	switch s {
	case keyTrashed:
		return fmt.Sprintf("A variável %s está na lixeira do projeto %s. Gravar uma versão nova a restaura. Continuar?", key, project)
	case keyNew:
		return fmt.Sprintf("A variável %s não existe no projeto %s. Criar?", key, project)
	}
	return ""
}

// secretState confere o nome e descobre o estado da variável, antes de o
// usuário digitar o valor. É usado pelo subcomando set e pelo modo
// interativo.
func secretState(ctx context.Context, c *client.Client, project, key string) (keyState, error) {
	// O servidor confere o nome de novo; conferir aqui evita digitar o
	// valor para depois ver o nome recusado.
	if err := checkKeyName(key); err != nil {
		return 0, err
	}
	// A lixeira exige a mesma permissão do PUT: quem não pode gravar
	// recebe o 403 aqui, antes de digitar o valor.
	trashed, err := c.Trash(ctx, project)
	if err != nil {
		return 0, err
	}
	metas, err := c.SecretsMeta(ctx, project)
	if err != nil {
		return 0, err
	}
	switch {
	case containsKey(metas, key):
		return keyExists, nil
	case containsTrashed(trashed, key):
		return keyTrashed, nil
	}
	return keyNew, nil
}

// checkKeyName aplica ao nome as mesmas regras do PUT no servidor.
func checkKeyName(key string) error {
	if err := envname.Check(key); err != nil {
		return err
	}
	if key == "meta" {
		return errors.New(`"meta" é reservado (é o caminho da listagem de nomes)`)
	}
	return nil
}

func containsKey(metas []client.SecretMeta, key string) bool {
	for _, m := range metas {
		if m.Key == key {
			return true
		}
	}
	return false
}

func containsTrashed(trashed []client.TrashedSecret, key string) bool {
	for _, t := range trashed {
		if t.Key == key {
			return true
		}
	}
	return false
}

func secretsUsage(w io.Writer) {
	fmt.Fprint(w, `Uso: envmem secrets <ação> [opções] [NOME]

Ações:
  list            lista os nomes das variáveis (nunca os valores); sem
                  --projeto, de todos os seus projetos
  get NOME        mostra o valor de uma variável (--versao N para uma antiga)
  set NOME        grava uma versão nova; o valor é pedido no terminal, sem
                  eco, ou lido do stdin com --valor-stdin
  rm NOME         manda a variável para a lixeira
  restore NOME    tira a variável da lixeira
  trash           lista a lixeira
  purge NOME      exclui de vez uma variável da lixeira (admin e superadmin)

O valor nunca é passado como argumento: iria para o histórico do shell e
apareceria no "ps". As opções vêm antes do nome:
  envmem secrets set --projeto demo DB_PASSWORD
  gerador-de-senha | envmem secrets set --projeto demo --valor-stdin --criar API_KEY
`)
}
