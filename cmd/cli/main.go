// Comando envmem: o CLI que busca os segredos de um projeto no envmem-server
// e os entrega a uma aplicação como variáveis de ambiente, só em memória.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// Sem argumentos, a Fatia 5b vai abrir o modo interativo. Por enquanto,
	// mostra a ajuda.
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "login":
		return cmdLogin(args[1:])
	case "logout":
		return cmdLogout(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "projects":
		return cmdProjects(args[1:])
	case "secrets":
		return cmdSecrets(args[1:])
	case "help", "-h", "-help", "--help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "envmem: subcomando desconhecido %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Uso: envmem <subcomando> [opções]

Subcomandos:
  login      abre uma sessão no servidor (pede a senha)
  logout     encerra a sessão e apaga o token deste computador
  run        executa um comando com os segredos do projeto no ambiente
  projects   lista, cria e remove projetos
  secrets    lista, lê, grava e remove variáveis de um projeto
  help       mostra esta ajuda

O login grava o servidor e a CA em ~/.config/envmem/config.json; nos
outros comandos, --servidor e --ca só são necessários para sobrescrevê-los.

Exemplos:
  envmem login --servidor https://localhost:8080 --ca certs/ca.crt voce@empresa.com
  envmem projects create demo
  envmem secrets set --projeto demo DB_PASSWORD
  envmem run --projeto demo -- sh -c 'echo $DB_PASSWORD'
`)
}
