package vault

import (
	"bytes"
	"errors"
	"testing"
)

var aadDemo = secretAAD("demo", "DB_PASSWORD")

func mustEncrypt(t *testing.T, master, plaintext, aad []byte) Envelope {
	t.Helper()
	env, err := encrypt(master, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return env
}

// 1. Ida e volta: o que foi cifrado volta igual.
func TestEnvelopeRoundTrip(t *testing.T) {
	master := GenerateKey()
	plaintext := []byte("senha-do-banco")

	env := mustEncrypt(t, master, plaintext, aadDemo)
	if bytes.Contains(env.Ciphertext, plaintext) {
		t.Fatal("o cifrado contém o texto em claro")
	}

	got, err := decrypt(master, env, aadDemo)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypt = %q, quero %q", got, plaintext)
	}
}

// 2. Texto adulterado falha: a tag do GCM detecta qualquer bit trocado.
func TestEnvelopeTamperedCiphertext(t *testing.T) {
	master := GenerateKey()
	env := mustEncrypt(t, master, []byte("senha"), aadDemo)

	env.Ciphertext[0] ^= 0x01
	if _, err := decrypt(master, env, aadDemo); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, quero ErrDecrypt", err)
	}
}

// 3. DEK errada falha: a DEK de outro envelope (mesma chave-mestra, mesmo
// contexto) abre normalmente, mas não decifra este valor.
func TestEnvelopeWrongDEK(t *testing.T) {
	master := GenerateKey()
	env := mustEncrypt(t, master, []byte("senha"), aadDemo)
	other := mustEncrypt(t, master, []byte("outra"), aadDemo)

	env.WrappedDEK, env.DEKNonce = other.WrappedDEK, other.DEKNonce
	if _, err := decrypt(master, env, aadDemo); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, quero ErrDecrypt", err)
	}
}

// 4. Chave-mestra errada falha: a DEK não abre.
func TestEnvelopeWrongMasterKey(t *testing.T) {
	env := mustEncrypt(t, GenerateKey(), []byte("senha"), aadDemo)

	if _, err := decrypt(GenerateKey(), env, aadDemo); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, quero ErrDecrypt", err)
	}
}

// AAD: o envelope de demo/DB_PASSWORD não abre como se fosse de outro
// projeto ou de outra chave, mesmo com a chave-mestra certa. É o que impede
// mover uma linha da tabela secrets para outro projeto pelo banco.
func TestEnvelopeAADBindsContext(t *testing.T) {
	master := GenerateKey()
	env := mustEncrypt(t, master, []byte("senha"), aadDemo)

	for _, aad := range [][]byte{
		secretAAD("app-prod", "DB_PASSWORD"),
		secretAAD("demo", "OUTRA_CHAVE"),
		secretAAD("dem", "oDB_PASSWORD"), // mesmos bytes concatenados
	} {
		if _, err := decrypt(master, env, aad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("abriu com contexto %q: err = %v", aad, err)
		}
	}
}

// Cifrar o mesmo valor duas vezes gera nonces, DEKs e cifrados diferentes.
func TestEnvelopeFreshNonceAndDEK(t *testing.T) {
	master := GenerateKey()
	a := mustEncrypt(t, master, []byte("igual"), aadDemo)
	b := mustEncrypt(t, master, []byte("igual"), aadDemo)

	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.DEKNonce, b.DEKNonce) {
		t.Error("nonce repetido")
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Error("cifrados iguais para o mesmo valor")
	}
}

// Nonce de tamanho errado (banco adulterado) vira erro, não panic.
func TestEnvelopeBadNonceLength(t *testing.T) {
	master := GenerateKey()
	env := mustEncrypt(t, master, []byte("senha"), aadDemo)

	env.DEKNonce = []byte("curto")
	if _, err := decrypt(master, env, aadDemo); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, quero ErrDecrypt", err)
	}
}

func TestDecodeKey(t *testing.T) {
	k := GenerateKey()
	got, err := DecodeKey(EncodeKey(k))
	if err != nil || !bytes.Equal(got, k) {
		t.Fatalf("ida e volta do base64 falhou: %v", err)
	}
	for _, bad := range []string{"", "não é base64!", EncodeKey(make([]byte, 16))} {
		if _, err := DecodeKey(bad); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("DecodeKey(%q) = %v, quero ErrInvalidKey", bad, err)
		}
	}
}
