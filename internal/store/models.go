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
	// ErrLastSuperadmin indica uma tentativa de remover o último superadmin.
	ErrLastSuperadmin = errors.New("store: é o último superadmin")
	// ErrNotSuperadmin indica que o usuário não é superadmin (reset-password
	// no servidor só vale para superadmin).
	ErrNotSuperadmin = errors.New("store: o usuário não é superadmin")
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
	DeletedAt  *time.Time // preenchido: na lixeira (decisão 11)
}

// SecretMeta descreve um segredo sem o valor: a chave, a versão atual,
// quantas versões estão guardadas e quando a atual foi gravada.
type SecretMeta struct {
	Key       string
	Version   int
	Versions  int
	UpdatedAt time.Time
}

// TrashedSecret é um segredo na lixeira (decisão 11).
type TrashedSecret struct {
	Key       string
	Version   int // última versão antes de ir para a lixeira
	DeletedAt time.Time
}

// VaultMeta é o valor de verificação do unseal (cifrado com a chave-mestra).
type VaultMeta struct {
	CheckCiphertext []byte
	CheckNonce      []byte
}
