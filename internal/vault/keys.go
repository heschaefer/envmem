// Package vault é o único pacote que cifra e decifra. Implementa o envelope
// encryption (envelope.go), as chaves (keys.go) e o seal/unseal (seal.go).
package vault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// KeySize é o tamanho, em bytes, da chave-mestra e de cada DEK: 32 bytes
// (256 bits) seleciona o AES-256.
const KeySize = 32

// ErrInvalidKey indica uma chave-mestra mal formada (base64 inválido ou
// tamanho diferente de KeySize). A mensagem nunca repete a chave.
var ErrInvalidKey = errors.New("chave-mestra inválida: esperados 32 bytes em base64")

// GenerateKey devolve uma chave nova de KeySize bytes, do gerador
// criptográfico do sistema operacional.
func GenerateKey() []byte {
	k := make([]byte, KeySize)
	// Desde o Go 1.24, crypto/rand.Read nunca devolve erro: se o sistema não
	// conseguir fornecer aleatoriedade, o programa é abortado, em vez de
	// continuar com uma chave fraca.
	rand.Read(k)
	return k
}

// EncodeKey codifica a chave em base64, para o keygen mostrar ao operador.
func EncodeKey(k []byte) string {
	return base64.StdEncoding.EncodeToString(k)
}

// DecodeKey decodifica a chave em base64 recebida no unseal.
func DecodeKey(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(k) != KeySize {
		zero(k)
		return nil, ErrInvalidKey
	}
	return k, nil
}

// zero sobrescreve b com zeros. Usado em toda chave em claro depois do uso,
// para que ela não fique na memória esperando o coletor de lixo.
func zero(b []byte) {
	clear(b)
}
