package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/heschaefer/envmem/internal/client"
)

func TestBuildEnv(t *testing.T) {
	base := []string{"PATH=/usr/bin", "HOME=/home/dev", "DB_PASSWORD=antiga"}
	secrets := []client.Secret{
		{Key: "DB_PASSWORD", Value: "nova"},
		{Key: "API_KEY", Value: "a=b=c"}, // "=" no valor é permitido
	}

	env, err := buildEnv(base, secrets)
	if err != nil {
		t.Fatalf("buildEnv: %v", err)
	}
	want := []string{"PATH=/usr/bin", "HOME=/home/dev", "DB_PASSWORD=nova", "API_KEY=a=b=c"}
	if !slices.Equal(env, want) {
		t.Errorf("env = %q\nquero %q", env, want)
	}
}

// As variáveis ENVMEM_* (do próprio envmem) não chegam à aplicação.
func TestBuildEnvDropsEnvmemVars(t *testing.T) {
	base := []string{"HOME=/home/dev", "ENVMEM_TOKEN=nao-pode-passar", "ENVMEM_X=y", "MY_ENVMEM_OK=1"}
	env, err := buildEnv(base, []client.Secret{{Key: "DB_PASSWORD", Value: "s"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"HOME=/home/dev", "MY_ENVMEM_OK=1", "DB_PASSWORD=s"}
	if !slices.Equal(env, want) {
		t.Errorf("env = %q\nquero %q", env, want)
	}
}

func TestBuildEnvRejects(t *testing.T) {
	tests := []struct {
		name    string
		secrets []client.Secret
	}{
		{"nome vazio", []client.Secret{{Key: "", Value: "x"}}},
		{"começa com dígito", []client.Secret{{Key: "1A", Value: "x"}}},
		// "PATH=/tmp/x" viraria "PATH=/tmp/x=v": um nome com "=" sobrescreveria
		// outra variável.
		{"nome com =", []client.Secret{{Key: "PATH=/tmp/x", Value: "v"}}},
		{"nome com espaço", []client.Secret{{Key: "A B", Value: "x"}}},
		{"nome com hífen", []client.Secret{{Key: "A-B", Value: "x"}}},
		// Nomes reservados: os casos completos estão em internal/envname.
		{"nome bloqueado", []client.Secret{{Key: "LD_PRELOAD", Value: "/tmp/x.so"}}},
		{"um bloqueado entre válidos", []client.Secret{{Key: "DB_PASSWORD", Value: "x"}, {Key: "PATH", Value: "/tmp"}}},
		{"valor com byte nulo", []client.Secret{{Key: "A", Value: "x\x00y"}}},
		{"chave repetida", []client.Secret{{Key: "A", Value: "1"}, {Key: "A", Value: "2"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := buildEnv(nil, tt.secrets); err == nil {
				t.Fatal("esperava erro")
			}
		})
	}
}

// helperEnv faz o binário de teste, quando reexecutado, agir como o
// "envmem run" em vez de rodar os testes. O valor diz se é com --verbose.
const helperEnv = "ENVMEM_TEST_EXEC_HELPER"

// runHelper roda, num processo filho, execWithSecrets com o comando
// sh -c 'echo "$$ $DB_PASSWORD"'. Devolve o PID do filho, stdout e stderr.
func runHelper(t *testing.T, testName, mode string) (pid int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("processo auxiliar: %v\nstderr: %s", err, errOut.String())
	}
	return cmd.Process.Pid, out.String(), errOut.String()
}

// helperExec é o lado do processo filho: faz o exec de verdade.
func helperExec(verbose bool) {
	err := execWithSecrets(
		[]string{"sh", "-c", `echo "$$ $DB_PASSWORD"`},
		[]client.Secret{{Key: "DB_PASSWORD", Value: "s3gr3do"}},
		verbose,
	)
	fmt.Fprintln(os.Stderr, "exec falhou:", err)
	os.Exit(3)
}

// TestExecKeepsPID prova o mecanismo central: o comando roda no MESMO PID do
// envmem (não é um processo filho) e recebe o segredo no ambiente.
//
// O teste reexecuta o próprio binário de teste como processo filho. Esse
// filho chama execWithSecrets com verbose, que imprime o PID e faz o exec de
// "sh". O shell imprime $$ (o próprio PID) e $DB_PASSWORD. Os três PIDs têm
// de ser iguais: o que o teste criou, o que o envmem imprimiu e o do shell.
func TestExecKeepsPID(t *testing.T) {
	if os.Getenv(helperEnv) == "verbose" {
		helperExec(true)
	}

	spawned, stdout, stderr := runHelper(t, "TestExecKeepsPID", "verbose")

	var printed int
	if _, err := fmt.Sscanf(stderr, "envmem: pid %d,", &printed); err != nil {
		t.Fatalf("PID não encontrado no stderr %q: %v", stderr, err)
	}

	var shellPID int
	var value string
	if _, err := fmt.Sscanf(strings.TrimSpace(stdout), "%d %s", &shellPID, &value); err != nil {
		t.Fatalf("saída inesperada do shell %q: %v", stdout, err)
	}

	if printed != spawned || shellPID != spawned {
		t.Errorf("PIDs diferentes: criado=%d, impresso pelo envmem=%d, do shell=%d", spawned, printed, shellPID)
	}
	if value != "s3gr3do" {
		t.Errorf("DB_PASSWORD no comando = %q, quero %q", value, "s3gr3do")
	}
}

// Sem --verbose, o envmem não escreve nada: a saída é só a do comando.
func TestExecQuiet(t *testing.T) {
	if os.Getenv(helperEnv) == "quiet" {
		helperExec(false)
	}

	spawned, stdout, stderr := runHelper(t, "TestExecQuiet", "quiet")
	if stderr != "" {
		t.Errorf("stderr deveria estar vazio, veio %q", stderr)
	}
	if want := fmt.Sprintf("%d s3gr3do\n", spawned); stdout != want {
		t.Errorf("stdout = %q, quero %q", stdout, want)
	}
}

func TestExecCommandNotFound(t *testing.T) {
	err := execWithSecrets([]string{"comando-que-nao-existe-envmem"}, nil, false)
	if err == nil {
		t.Fatal("esperava erro")
	}
}
