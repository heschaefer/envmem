package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/heschaefer/envmem/internal/client"
)

// execWithSecrets substitui o processo do envmem pelo comando, com os
// segredos somados ao ambiente atual. Se der certo, não retorna: o PID passa
// a ser do comando e o envmem deixa de existir. Só retorna em caso de erro.
func execWithSecrets(command []string, secrets []client.Secret) error {
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}

	env, err := buildEnv(os.Environ(), secrets)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "envmem: pid %d, exec %s\n", os.Getpid(), path)
	return syscall.Exec(path, command, env)
}

// buildEnv devolve base mais os segredos, no formato "CHAVE=valor". Um
// segredo substitui a variável de mesmo nome que já exista em base.
func buildEnv(base []string, secrets []client.Secret) ([]string, error) {
	replaced := make(map[string]bool, len(secrets))
	for _, s := range secrets {
		if !validEnvName(s.Key) {
			return nil, fmt.Errorf("nome de variável inválido vindo do servidor: %q", s.Key)
		}
		if replaced[s.Key] {
			return nil, fmt.Errorf("segredo %s repetido na resposta do servidor", s.Key)
		}
		if strings.IndexByte(s.Value, 0) >= 0 {
			return nil, fmt.Errorf("valor do segredo %s contém byte nulo", s.Key)
		}
		replaced[s.Key] = true
	}

	env := make([]string, 0, len(base)+len(secrets))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if !replaced[name] {
			env = append(env, kv)
		}
	}
	for _, s := range secrets {
		env = append(env, s.Key+"="+s.Value)
	}
	return env, nil
}

// validEnvName aceita nomes no formato portável do POSIX: letras, dígitos e
// "_", sem começar por dígito.
func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		switch {
		case c == '_', 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z':
		case '0' <= c && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
