package auth

import (
	"errors"
	"net/mail"
	"strings"
)

// ErrInvalidEmail indica um e-mail fora do formato aceito.
var ErrInvalidEmail = errors.New("e-mail inválido")

// NormalizeEmail devolve o e-mail em minúsculas e sem espaços nas pontas,
// que é a forma guardada no banco (a tabela users confere com um CHECK).
// Assim, "Fulano@Empresa.com" e "fulano@empresa.com" são o mesmo usuário.
// Recusa formatos com nome ("Fulano <f@e.com>") ou com mais de um endereço.
func NormalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Name != "" || addr.Address != s || len(s) > 254 {
		return "", ErrInvalidEmail
	}
	return s, nil
}
