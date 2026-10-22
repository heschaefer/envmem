// Package envname valida nomes de segredos, que viram nomes de variáveis de
// ambiente no "envmem run". É usado pelo CLI, antes de injetar, e (a partir
// da Fatia 2) pelo servidor, antes de gravar.
package envname

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalid indica um nome fora do formato portável do POSIX.
	ErrInvalid = errors.New("nome de variável inválido")
	// ErrBlocked indica um nome que muda o comportamento de programas na
	// máquina de quem roda o "envmem run" (ver blockedNames).
	ErrBlocked = errors.New("nome de variável reservado")
)

// blockedNames são variáveis que fazem programas carregarem ou executarem
// código, ou trocarem os binários usados. Um segredo com um desses nomes
// daria a quem pode gravar segredos (gestor, admin) uma forma de executar
// código no computador dos desenvolvedores. A lista é uma camada a mais, não
// uma barreira completa: existem outras variáveis desse tipo.
var blockedNames = map[string]bool{
	// Busca de executáveis e shells.
	"PATH": true, "IFS": true, "ENV": true, "BASH_ENV": true,
	"SHELLOPTS": true, "BASHOPTS": true, "PS4": true, "PROMPT_COMMAND": true,
	// Interpretadores e runtimes que carregam código indicado no ambiente.
	"NODE_OPTIONS": true,
	"PYTHONPATH":   true, "PYTHONHOME": true, "PYTHONSTARTUP": true,
	"PERL5OPT": true, "PERL5LIB": true, "PERLLIB": true,
	"RUBYOPT": true, "RUBYLIB": true,
	"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true,
	"GOFLAGS":    true,
	"GCONV_PATH": true,
	// Programas que executam um comando indicado na variável.
	"EDITOR": true, "VISUAL": true, "PAGER": true,
	"LESSOPEN": true, "LESSCLOSE": true,
	"SSH_ASKPASS": true, "SUDO_ASKPASS": true,
}

// blockedPrefixes cobrem famílias inteiras de variáveis.
var blockedPrefixes = []string{
	"LD_",         // carregador dinâmico do Linux (LD_PRELOAD, LD_LIBRARY_PATH...)
	"DYLD_",       // carregador dinâmico do macOS
	"GIT_",        // GIT_SSH_COMMAND, GIT_EXEC_PATH, GIT_CONFIG_*...
	"NPM_CONFIG_", // npm_config_script_shell e similares
	"ENVMEM_",     // do próprio envmem; o run as descarta do ambiente da aplicação
}

// Check devolve nil se name pode ser usado como nome de segredo. O erro
// envolve ErrInvalid ou ErrBlocked e cita o nome (nunca um valor).
func Check(name string) error {
	if !valid(name) {
		return fmt.Errorf("%w: %q (use letras, dígitos e _, sem começar por dígito)", ErrInvalid, name)
	}
	// Comparação em maiúsculas: alguns programas também leem o nome em
	// minúsculas (o npm lê npm_config_*).
	upper := strings.ToUpper(name)
	if blockedNames[upper] {
		return fmt.Errorf("%w: %s", ErrBlocked, name)
	}
	for _, p := range blockedPrefixes {
		if strings.HasPrefix(upper, p) {
			return fmt.Errorf("%w: %s (prefixo %s)", ErrBlocked, name, p)
		}
	}
	return nil
}

// valid aceita nomes no formato portável do POSIX: letras, dígitos e "_",
// sem começar por dígito. Isso também exclui "=" (que permitiria
// sobrescrever outra variável) e "%" (usado pelo bash em funções exportadas).
func valid(name string) bool {
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
