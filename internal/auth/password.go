// Package auth reúne autenticação e autorização do envmem-server: hash de
// senhas, tokens de sessão e permissões.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Parâmetros do argon2id: os mínimos recomendados pela OWASP (19 MiB de
// memória, 2 iterações, paralelismo 1). Eles vão gravados junto com cada
// hash, então podem ser aumentados no futuro sem invalidar as senhas que
// já existem: cada uma é conferida com os parâmetros com que foi gerada.
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	saltLen        = 16
)

// Limites de tamanho da senha (decisão 47). Não há regras de composição
// (maiúscula, número, símbolo): elas levam a senhas previsíveis, como
// "Senha@2026". O máximo só limita o tamanho da entrada.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 128
)

var (
	// ErrPasswordPolicy indica senha fora dos limites de tamanho.
	ErrPasswordPolicy = fmt.Errorf("a senha precisa ter de %d a %d caracteres", MinPasswordLen, MaxPasswordLen)
	// ErrInvalidHash indica um hash gravado fora do formato esperado.
	ErrInvalidHash = errors.New("auth: hash de senha em formato inválido")
)

// CheckPasswordPolicy confere o tamanho da senha, em caracteres (não em
// bytes: "ç" conta como um).
func CheckPasswordPolicy(password []byte) error {
	if !utf8.Valid(password) {
		return ErrPasswordPolicy
	}
	n := utf8.RuneCount(password)
	if n < MinPasswordLen || n > MaxPasswordLen {
		return ErrPasswordPolicy
	}
	return nil
}

// HashPassword gera o hash argon2id da senha com um sal aleatório novo e
// devolve tudo numa string no formato PHC:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<sal em base64>$<hash em base64>
//
// O sal aleatório faz duas senhas iguais terem hashes diferentes, o que
// impede comparar usuários e usar tabelas pré-calculadas. Quem chama
// continua dono de password e deve zerá-la.
func HashPassword(password []byte) string {
	salt := make([]byte, saltLen)
	rand.Read(salt)
	key := argon2.IDKey(password, salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	defer clear(key)

	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

// VerifyPassword confere a senha contra um hash gerado por HashPassword,
// usando os parâmetros gravados no próprio hash.
func VerifyPassword(encoded string, password []byte) (bool, error) {
	p, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey(password, p.salt, p.time, p.memory, p.threads, uint32(len(p.key)))
	defer clear(key)

	// Comparação em tempo constante: com bytes.Equal, o tempo de resposta
	// variaria conforme o primeiro byte diferente, e um atacante poderia
	// usar essa diferença para descobrir o hash aos poucos.
	return subtle.ConstantTimeCompare(key, p.key) == 1, nil
}

// dummyHash é o hash de uma senha aleatória, calculado uma vez. O login
// com e-mail inexistente confere a senha contra ele: assim a resposta leva
// o mesmo tempo de um e-mail que existe, e o tempo não revela quais
// e-mails estão cadastrados.
var dummyHash = sync.OnceValue(func() string {
	b := make([]byte, 32)
	rand.Read(b)
	return HashPassword(b)
})

// VerifyDummy gasta o mesmo tempo de VerifyPassword e sempre devolve false.
func VerifyDummy(password []byte) bool {
	VerifyPassword(dummyHash(), password)
	return false
}

type hashParams struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

// parseHash lê uma string no formato PHC. O hash vem do banco, então é
// conferido campo a campo: um valor adulterado vira erro, não pânico nem
// um custo absurdo de memória.
func parseHash(encoded string) (hashParams, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", sal, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return hashParams{}, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return hashParams{}, ErrInvalidHash
	}
	var p hashParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return hashParams{}, ErrInvalidHash
	}
	// Limites de sanidade: protegem o servidor de um hash adulterado no
	// banco que pedisse, por exemplo, 4 GiB de memória por tentativa.
	if p.memory < 8*1024 || p.memory > 256*1024 || p.time < 1 || p.time > 10 || p.threads < 1 || p.threads > 4 {
		return hashParams{}, ErrInvalidHash
	}
	var err error
	b64 := base64.RawStdEncoding
	if p.salt, err = b64.DecodeString(parts[4]); err != nil || len(p.salt) < saltLen {
		return hashParams{}, ErrInvalidHash
	}
	if p.key, err = b64.DecodeString(parts[5]); err != nil || len(p.key) < 16 {
		return hashParams{}, ErrInvalidHash
	}
	return p, nil
}
