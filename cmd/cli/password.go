package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

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
