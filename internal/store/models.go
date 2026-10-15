package store

import (
	"errors"
	"time"
)

var (
	// ErrNotFound indica que o registro procurado não existe.
	ErrNotFound = errors.New("store: não encontrado")
	// ErrConflict indica que outra gravação ocupou a mesma posição (por
	// exemplo, duas versões novas do mesmo segredo ao mesmo tempo).
	ErrConflict = errors.New("store: conflito de gravação")
)

// SecretRow é uma versão de segredo como está no banco: só material cifrado.
type SecretRow struct {
	Project    string
	Key        string
	Version    int
	Ciphertext []byte // valor cifrado com a DEK
	Nonce      []byte // nonce da cifragem do valor
	WrappedDEK []byte // DEK cifrada com a chave-mestra
	DEKNonce   []byte // nonce da cifragem da DEK
	CreatedAt  time.Time
}

// VaultMeta é o valor de verificação do unseal (cifrado com a chave-mestra).
type VaultMeta struct {
	CheckCiphertext []byte
	CheckNonce      []byte
}
