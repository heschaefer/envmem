package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// readPassword pede uma senha no terminal, sem eco: o que é digitado não
// aparece na tela nem vai para o histórico do shell. Com fromStdin, lê uma
// linha do stdin, para uso em scripts. A senha nunca vem por argumento,
// porque argumentos aparecem no "ps".
func readPassword(prompt string, fromStdin bool) ([]byte, error) {
	if fromStdin {
		return readLine(os.Stdin)
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("o stdin não é um terminal; use --senha-stdin para ler a senha de um pipe")
	}
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return p, err
}

// readNewPassword pede uma senha nova duas vezes, no terminal, e confere
// que as duas são iguais.
func readNewPassword() ([]byte, error) {
	first, err := readPassword("Nova senha (de 12 a 128 caracteres): ", false)
	if err != nil {
		return nil, err
	}
	second, err := readPassword("Repita a nova senha: ", false)
	defer clear(second)
	if err != nil {
		clear(first)
		return nil, err
	}
	if !bytes.Equal(first, second) {
		clear(first)
		return nil, errors.New("as senhas não conferem")
	}
	return first, nil
}

// readLine lê uma linha de r, sem o "\n" (nem o "\r" do Windows).
func readLine(r io.Reader) ([]byte, error) {
	line, err := bufio.NewReader(r).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

// maxValueBytes limita o valor de segredo lido do stdin. O servidor aceita
// corpos de até 64 KiB; com o JSON em volta, um valor desse tamanho já
// seria recusado lá, mas o limite aqui evita ler um pipe sem fim.
const maxValueBytes = 64 << 10

// readSecretValue lê o valor de um segredo. No terminal, pede duas vezes,
// sem eco, como a senha. Com fromStdin, lê o stdin inteiro (o valor pode
// ter várias linhas, como uma chave PEM) e tira só a quebra de linha
// final que o echo acrescenta. O valor nunca vem por argumento: iria para
// o histórico do shell e apareceria no "ps".
func readSecretValue(fromStdin bool) ([]byte, error) {
	if fromStdin {
		v, err := io.ReadAll(io.LimitReader(os.Stdin, maxValueBytes+1))
		if err != nil {
			return nil, err
		}
		if len(v) > maxValueBytes {
			clear(v)
			return nil, fmt.Errorf("o valor passa de %d KiB", maxValueBytes>>10)
		}
		v = bytes.TrimSuffix(v, []byte("\n"))
		return bytes.TrimSuffix(v, []byte("\r")), nil
	}
	first, err := readPassword("Valor (não aparece na tela): ", false)
	if err != nil {
		return nil, err
	}
	second, err := readPassword("Repita o valor: ", false)
	defer clear(second)
	if err != nil {
		clear(first)
		return nil, err
	}
	if !bytes.Equal(first, second) {
		clear(first)
		return nil, errors.New("os valores não conferem")
	}
	return first, nil
}

// confirm faz uma pergunta de sim ou não no terminal. Só "s" ou "sim"
// confirmam; qualquer outra resposta (inclusive Enter) é não.
func confirm(question string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errors.New("o stdin não é um terminal; não há como confirmar")
	}
	fmt.Fprintf(os.Stderr, "%s [s/N] ", question)
	line, err := readLine(os.Stdin)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(string(line))) {
	case "s", "sim":
		return true, nil
	}
	return false, nil
}
