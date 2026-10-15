package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/heschaefer/envmem/internal/client"
	"github.com/heschaefer/envmem/internal/envname"
)

// execWithSecrets substitui o processo do envmem pelo comando, com os
// segredos somados ao ambiente atual. Se der certo, não retorna: o PID passa
// a ser do comando e o envmem deixa de existir. Só retorna em caso de erro.
// Com verbose, imprime o PID antes do exec (usado na demonstração).
func execWithSecrets(command []string, secrets []client.Secret, verbose bool) error {
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}

	env, err := buildEnv(os.Environ(), secrets)
	if err != nil {
		return err
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "envmem: pid %d, exec %s\n", os.Getpid(), path)
	}
	return syscall.Exec(path, command, env)
}

// buildEnv devolve base mais os segredos, no formato "CHAVE=valor". Um
// segredo substitui a variável de mesmo nome que já exista em base.
func buildEnv(base []string, secrets []client.Secret) ([]string, error) {
	replaced := make(map[string]bool, len(secrets))
	for _, s := range secrets {
		// Defesa em profundidade: o servidor também confere o nome ao gravar
		// (Fatia 2), mas o CLI não confia nisso. Se um nome perigoso chegar,
		// nada é executado.
		if err := envname.Check(s.Key); err != nil {
			return nil, fmt.Errorf("segredo recusado: %w", err)
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
