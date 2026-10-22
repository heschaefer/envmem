package auth

import (
	"bytes"
	"testing"
)

func TestNewToken(t *testing.T) {
	a, ha := NewToken()
	b, hb := NewToken()
	if a == b || bytes.Equal(ha, hb) {
		t.Fatal("dois tokens iguais")
	}
	if len(a) != 43 || len(ha) != 32 {
		t.Fatalf("tamanhos: token %d, hash %d", len(a), len(ha))
	}
	if !bytes.Equal(HashToken(a), ha) {
		t.Fatal("HashToken não reproduz o hash do NewToken")
	}
	if bytes.Contains(ha, []byte(a)) {
		t.Fatal("o hash contém o token")
	}
}

func TestHashTokenRejectsMalformed(t *testing.T) {
	for _, s := range []string{"", "curto", string(make([]byte, 1000))} {
		if HashToken(s) != nil {
			t.Errorf("HashToken(%d bytes) deveria ser nil", len(s))
		}
	}
}
