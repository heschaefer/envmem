package vault

import (
	"bytes"
	"errors"
	"testing"
)

// unsealed devolve um cofre aberto com uma chave nova.
func unsealed(t *testing.T) (*Vault, []byte) {
	t.Helper()
	key := GenerateKey()
	ct, nonce, err := NewCheckValue(key)
	if err != nil {
		t.Fatal(err)
	}
	v := New()
	if err := v.Unseal(key, ct, nonce); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	return v, key
}

func TestStartsSealed(t *testing.T) {
	v := New()
	if !v.Sealed() {
		t.Fatal("o cofre deveria começar selado")
	}
	if _, err := v.EncryptSecret("demo", "K", []byte("x")); !errors.Is(err, ErrSealed) {
		t.Errorf("EncryptSecret selado: %v, quero ErrSealed", err)
	}
	if _, err := v.DecryptSecret("demo", "K", Envelope{}); !errors.Is(err, ErrSealed) {
		t.Errorf("DecryptSecret selado: %v, quero ErrSealed", err)
	}
}

func TestUnsealWithCorrectKey(t *testing.T) {
	v, _ := unsealed(t)
	if v.Sealed() {
		t.Fatal("deveria estar aberto")
	}

	env, err := v.EncryptSecret("demo", "DB_PASSWORD", []byte("senha"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.DecryptSecret("demo", "DB_PASSWORD", env)
	if err != nil || string(got) != "senha" {
		t.Fatalf("DecryptSecret = %q, %v", got, err)
	}
	// Outro projeto: o AAD não confere.
	if _, err := v.DecryptSecret("app-prod", "DB_PASSWORD", env); !errors.Is(err, ErrDecrypt) {
		t.Errorf("abriu em outro projeto: %v", err)
	}
}

func TestUnsealWithWrongKey(t *testing.T) {
	ct, nonce, err := NewCheckValue(GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	v := New()
	if err := v.Unseal(GenerateKey(), ct, nonce); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("Unseal com chave errada: %v, quero ErrWrongKey", err)
	}
	if !v.Sealed() {
		t.Fatal("chave errada não pode abrir o cofre")
	}
}

func TestUnsealTwice(t *testing.T) {
	key := GenerateKey()
	ct, nonce, _ := NewCheckValue(key)
	v := New()
	if err := v.Unseal(key, ct, nonce); err != nil {
		t.Fatal(err)
	}
	if err := v.Unseal(key, ct, nonce); !errors.Is(err, ErrAlreadyUnsealed) {
		t.Fatalf("segundo Unseal: %v, quero ErrAlreadyUnsealed", err)
	}
}

// O cofre guarda uma cópia: zerar a chave de quem chamou não afeta o cofre.
func TestUnsealCopiesKey(t *testing.T) {
	v, key := unsealed(t)
	env, _ := v.EncryptSecret("demo", "K", []byte("x"))

	clear(key)
	if _, err := v.DecryptSecret("demo", "K", env); err != nil {
		t.Fatalf("o cofre dependia da fatia de quem chamou: %v", err)
	}
}

// Seal zera a chave em memória e volta a recusar operações.
func TestSeal(t *testing.T) {
	v, _ := unsealed(t)
	inMemory := v.masterKey

	v.Seal()
	if !v.Sealed() {
		t.Fatal("deveria estar selado")
	}
	if !bytes.Equal(inMemory, make([]byte, KeySize)) {
		t.Error("a chave-mestra não foi zerada")
	}
	if _, err := v.EncryptSecret("demo", "K", []byte("x")); !errors.Is(err, ErrSealed) {
		t.Errorf("EncryptSecret depois do Seal: %v", err)
	}
}
