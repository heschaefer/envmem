package main

import (
	"errors"
	"fmt"
	"strings"
)

// splitCommand transforma a linha digitada em "Rodar um comando" (modo
// interativo) nos argumentos do syscall.Exec, sem shell: o processo do
// envmem vira a própria aplicação, como no "envmem run -- comando args".
//
// Espaços separam os argumentos; aspas simples agrupam tudo até a próxima
// aspa simples; aspas duplas agrupam até a próxima aspa dupla, e dentro
// delas a barra invertida só escapa " e \; fora das aspas, a barra
// invertida escapa o caractere seguinte.
//
// Fora das aspas, os caracteres que o shell interpretaria (| & ; < > $ e
// a crase) são recusados: como não há shell, eles chegariam ao programa
// como texto, o que surpreenderia quem espera um pipe ou uma variável.
// Quem precisa de shell usa "sh -c '...'", como no subcomando run.
func splitCommand(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inArg := false // distingue "nenhum argumento" de um argumento vazio ('')

	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case ch == ' ' || ch == '\t':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		case ch == '\'':
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("aspa simples sem fechamento")
			}
			cur.WriteString(line[i+1 : i+1+end])
			i += end + 1
			inArg = true
		case ch == '"':
			closed := false
			for i++; i < len(line); i++ {
				if line[i] == '"' {
					closed = true
					break
				}
				if line[i] == '\\' && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\\') {
					i++
				}
				cur.WriteByte(line[i])
			}
			if !closed {
				return nil, errors.New("aspa dupla sem fechamento")
			}
			inArg = true
		case ch == '\\':
			if i+1 == len(line) {
				return nil, errors.New("barra invertida no fim da linha")
			}
			i++
			cur.WriteByte(line[i])
			inArg = true
		case strings.IndexByte("|&;<>$`", ch) >= 0:
			return nil, fmt.Errorf("%q não funciona aqui: o comando roda sem shell (sem pipes, redirecionamentos nem variáveis); "+
				"ponha entre aspas para passar o caractere ao programa", ch)
		default:
			cur.WriteByte(ch)
			inArg = true
		}
	}
	if inArg {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("digite um comando")
	}
	return args, nil
}
