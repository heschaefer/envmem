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
	// ErrProjectNotEmpty indica uma tentativa de apagar um projeto que
	// ainda tem segredos.
	ErrProjectNotEmpty = errors.New("store: projeto tem segredos")
	// ErrSuperadminExists indica que já existe um superadmin, então o
	// create-superadmin (só para o primeiro) não roda.
	ErrSuperadminExists = errors.New("store: já existe um superadmin")
)

// Papéis globais. Um usuário sem papel global tem GlobalRole vazio (NULL no
// banco) e só acessa os projetos de que é membro.
const (
	RoleSuperadmin = "superadmin"
	RoleAdmin      = "admin"
)

// User é um usuário do envmem. PasswordHash é o argon2id no formato PHC;
// a senha em claro nunca chega ao store.
type User struct {
	ID           string
	Email        string
	GlobalRole   string // RoleSuperadmin, RoleAdmin ou ""
	PasswordHash string
	// TempPasswordExpiresAt preenchido indica senha temporária (decisão
	// 43): troca obrigatória no primeiro login, e não entra depois desse
	// instante. Nil indica senha definitiva.
	TempPasswordExpiresAt *time.Time
	CreatedAt             time.Time
}

// Project é um projeto. Cada ambiente (app-prod, app-homo) é um projeto.
type Project struct {
	ID        string // uuid; é o que entra no AAD dos segredos
	Name      string // nome usado nas rotas e no CLI
	CreatedAt time.Time
}

// SecretRow é uma versão de segredo como está no banco: só material cifrado.
type SecretRow struct {
	ProjectID  string
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
