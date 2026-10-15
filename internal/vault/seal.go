package vault

import (
	"bytes"
	"errors"
	"sync"
)

var (
	// ErrSealed indica que o cofre está selado: a chave-mestra não está em
	// memória, então nada pode ser cifrado nem decifrado.
	ErrSealed = errors.New("cofre selado")
	// ErrWrongKey indica que a chave do unseal não decifra o valor de
	// verificação, ou seja, não é a chave-mestra deste cofre.
	ErrWrongKey = errors.New("chave-mestra incorreta")
	// ErrAlreadyUnsealed indica um unseal com o cofre já aberto.
	ErrAlreadyUnsealed = errors.New("cofre já está aberto")
)

// O valor de verificação é este texto conhecido, cifrado com a chave-mestra
// e com um AAD próprio (diferente do AAD dos segredos, para que um não possa
// ser usado no lugar do outro).
var (
	checkPlaintext = []byte("envmem: chave-mestra correta")
	checkAAD       = []byte("envmem/vault-check/v1")
)

// Vault guarda a chave-mestra só em memória. Começa selado.
type Vault struct {
	// mu protege masterKey. Cifrar e decifrar seguram o lock de leitura
	// durante toda a operação; Seal pega o lock de escrita, então só zera
	// a chave depois que as operações em andamento terminarem.
	mu        sync.RWMutex
	masterKey []byte // nil enquanto selado
}

// New devolve um cofre selado.
func New() *Vault {
	return &Vault{}
}

// Sealed diz se o cofre está selado.
func (v *Vault) Sealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.masterKey == nil
}

// NewCheckValue cifra o valor de verificação com key. Usado só no primeiro
// unseal, quando o banco ainda não tem valor de verificação; quem chama
// grava o resultado em vault_meta.
func NewCheckValue(key []byte) (ciphertext, nonce []byte, err error) {
	return gcmSeal(key, checkPlaintext, checkAAD)
}

// Unseal confere key contra o valor de verificação gravado e, se for a
// chave certa, guarda uma cópia dela em memória. Quem chama continua dono
// de key e deve zerá-la.
func (v *Vault) Unseal(key, checkCiphertext, checkNonce []byte) error {
	// Se o GCM abrir o valor de verificação, a tag de autenticação já prova
	// que a chave é a mesma que o cifrou. A comparação do texto é uma
	// conferência a mais.
	plaintext, err := gcmOpen(key, checkCiphertext, checkNonce, checkAAD)
	if err != nil || !bytes.Equal(plaintext, checkPlaintext) {
		return ErrWrongKey
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masterKey != nil {
		return ErrAlreadyUnsealed
	}
	v.masterKey = bytes.Clone(key)
	return nil
}

// Seal zera a chave-mestra e a descarta. Por enquanto só é usado nos
// testes; a rota POST /v1/seal (superadmin) entra na Fatia 4.
func (v *Vault) Seal() {
	v.mu.Lock()
	defer v.mu.Unlock()
	zero(v.masterKey)
	v.masterKey = nil
}

// EncryptSecret cifra o valor de um segredo, amarrado ao projeto e à chave.
func (v *Vault) EncryptSecret(project, key string, value []byte) (Envelope, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.masterKey == nil {
		return Envelope{}, ErrSealed
	}
	return encrypt(v.masterKey, value, secretAAD(project, key))
}

// DecryptSecret decifra o valor de um segredo. Falha se o envelope não for
// deste projeto e desta chave. Quem chama deve zerar o resultado.
func (v *Vault) DecryptSecret(project, key string, env Envelope) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.masterKey == nil {
		return nil, ErrSealed
	}
	return decrypt(v.masterKey, env, secretAAD(project, key))
}
