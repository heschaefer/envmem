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
	case "run":
		return cmdRun(args[1:])
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
  run    executa um comando com os segredos do projeto no ambiente
  help   mostra esta ajuda

Exemplo:
  envmem run --projeto demo -- sh -c 'echo $DB_PASSWORD'
`)
}
