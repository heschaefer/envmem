package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// ErrDecrypt indica que a decifragem falhou: chave errada, dado adulterado
// ou contexto (AAD) diferente. De propósito, não diz qual dos casos foi.
var ErrDecrypt = errors.New("falha ao decifrar")

// Envelope é o resultado do envelope encryption de um valor: o valor cifrado
// com uma DEK própria e a DEK cifrada com a chave-mestra. É exatamente o
// que vai para o banco; nada aqui está em claro.
type Envelope struct {
	Ciphertext []byte // valor cifrado com a DEK (inclui a tag do GCM)
	Nonce      []byte // nonce da cifragem do valor
	WrappedDEK []byte // DEK cifrada com a chave-mestra (inclui a tag)
	DEKNonce   []byte // nonce da cifragem da DEK
}

// encrypt cifra plaintext com uma DEK nova e cifra a DEK com masterKey.
// O aad (contexto) entra nas duas cifragens: o envelope só abre de novo
// com o mesmo aad.
func encrypt(masterKey, plaintext, aad []byte) (Envelope, error) {
	dek := GenerateKey()
	defer zero(dek)

	ciphertext, nonce, err := gcmSeal(dek, plaintext, aad)
	if err != nil {
		return Envelope{}, err
	}
	wrappedDEK, dekNonce, err := gcmSeal(masterKey, dek, aad)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		WrappedDEK: wrappedDEK,
		DEKNonce:   dekNonce,
	}, nil
}

// decrypt faz o caminho inverso: decifra a DEK com masterKey e o valor com
// a DEK. Quem chama deve zerar o resultado depois de usá-lo.
func decrypt(masterKey []byte, env Envelope, aad []byte) ([]byte, error) {
	dek, err := gcmOpen(masterKey, env.WrappedDEK, env.DEKNonce, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer zero(dek)

	plaintext, err := gcmOpen(dek, env.Ciphertext, env.Nonce, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// gcmSeal cifra com AES-256-GCM usando um nonce novo e aleatório.
func gcmSeal(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	// Nonce de 12 bytes do crypto/rand a cada cifragem. No GCM, repetir um
	// nonce com a mesma chave quebra a confidencialidade e a autenticidade.
	// Cada DEK cifra um único valor, e a chave-mestra cifra uma DEK por
	// versão de segredo: muito abaixo do limite seguro de 2^32 cifragens
	// com nonce aleatório por chave.
	nonce = make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// gcmOpen decifra e confere a tag de autenticação. Se o cifrado, o nonce ou
// o aad tiverem sido alterados, ou a chave for outra, devolve erro.
func gcmOpen(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	// gcm.Open entra em panic com nonce de tamanho errado; o nonce vem do
	// banco, então é conferido antes.
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// secretAAD monta o contexto de um segredo: o rótulo, o projeto e a chave,
// cada um precedido do seu tamanho. O tamanho evita ambiguidade: sem ele,
// ("ab", "c") e ("a", "bc") gerariam os mesmos bytes.
func secretAAD(project, key string) []byte {
	b := []byte("envmem/secret/v1")
	b = binary.AppendUvarint(b, uint64(len(project)))
	b = append(b, project...)
	b = binary.AppendUvarint(b, uint64(len(key)))
	b = append(b, key...)
	return b
}
