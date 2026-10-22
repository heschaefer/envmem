package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// SessionTTL é a validade de uma sessão (decisão 3). É absoluta: conta a
// partir do login, e usar a sessão não a prolonga.
const SessionTTL = 8 * time.Hour

// tokenBytes é o tamanho do token: 32 bytes (256 bits) do crypto/rand,
// impossível de adivinhar.
const tokenBytes = 32

// tokenLen é o tamanho do token em base64 sem preenchimento.
var tokenLen = base64.RawURLEncoding.EncodedLen(tokenBytes)

// NewToken gera um token de sessão opaco (decisão 3) e o hash dele. O token
// vai uma única vez para o cliente; o servidor guarda só o hash. Quem lê a
// tabela de sessões, então, não encontra nenhum token utilizável.
func NewToken() (token string, hash []byte) {
	b := make([]byte, tokenBytes)
	rand.Read(b)
	token = base64.RawURLEncoding.EncodeToString(b)
	clear(b)
	return token, HashToken(token)
}

// HashToken devolve o SHA-256 do token. Um hash rápido basta aqui, ao
// contrário das senhas: o token tem 256 bits aleatórios, então não existe
// lista de candidatos prováveis para testar. Devolve nil para um texto que
// não tem o formato de token, que então não confere com sessão nenhuma.
func HashToken(token string) []byte {
	if len(token) != tokenLen {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
