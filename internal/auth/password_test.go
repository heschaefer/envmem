package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	password := []byte("correto cavalo bateria grampo")
	encoded := HashPassword(password)

	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("formato inesperado: %s", encoded)
	}
	if strings.Contains(encoded, string(password)) {
		t.Fatal("o hash contém a senha em claro")
	}
	if ok, err := VerifyPassword(encoded, password); err != nil || !ok {
		t.Fatalf("senha certa: %v, %v", ok, err)
	}
	if ok, err := VerifyPassword(encoded, []byte("correto cavalo bateria grampO")); err != nil || ok {
		t.Fatalf("senha errada aceita: %v, %v", ok, err)
	}
}

// O sal aleatório faz a mesma senha gerar hashes diferentes.
func TestSamePasswordDifferentHashes(t *testing.T) {
	a, b := HashPassword([]byte("mesma senha longa")), HashPassword([]byte("mesma senha longa"))
	if a == b {
		t.Fatal("dois hashes iguais para a mesma senha: o sal não é aleatório")
	}
}

// Os parâmetros vêm do próprio hash: um hash gerado com outros valores
// (por exemplo, antes de um aumento de custo) continua sendo conferido.
func TestVerifyUsesStoredParams(t *testing.T) {
	encoded := HashPassword([]byte("senha de teste longa"))
	// Troca t=2 por t=3 sem recalcular o hash: os parâmetros fazem parte da
	// conta, então a senha certa deixa de conferir.
	tampered := strings.Replace(encoded, "t=2", "t=3", 1)
	if ok, err := VerifyPassword(tampered, []byte("senha de teste longa")); err != nil || ok {
		t.Fatalf("parâmetro adulterado aceito: %v, %v", ok, err)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	valid := HashPassword([]byte("senha de teste longa"))
	parts := strings.Split(valid, "$")
	tests := map[string]string{
		"vazio":              "",
		"outro algoritmo":    strings.Replace(valid, "argon2id", "argon2i", 1),
		"versão errada":      strings.Replace(valid, "v=19", "v=16", 1),
		"memória absurda":    strings.Replace(valid, "m=19456", "m=4194304", 1),
		"sal curto":          strings.Join([]string{"", parts[1], parts[2], parts[3], "AAAA", parts[5]}, "$"),
		"base64 inválido":    strings.Join([]string{"", parts[1], parts[2], parts[3], parts[4], "!!!"}, "$"),
		"campos a menos":     strings.Join(parts[:5], "$"),
		"bcrypt (outro fmt)": "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyPassword(encoded, []byte("x")); !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("erro = %v, quero ErrInvalidHash", err)
			}
		})
	}
}

func TestPasswordPolicy(t *testing.T) {
	tests := []struct {
		password string
		ok       bool
	}{
		{"onze chars!", false},
		{"doze chars!!", true},
		{"ççççççççççç", false}, // 11 caracteres, 22 bytes: conta caracteres
		{"çççççççççççç", true}, // 12 caracteres
		{strings.Repeat("a", 128), true},
		{strings.Repeat("a", 129), false},
		{"\xff\xfe inválido utf-8", false},
	}
	for _, tt := range tests {
		err := CheckPasswordPolicy([]byte(tt.password))
		if (err == nil) != tt.ok {
			t.Errorf("CheckPasswordPolicy(%q) = %v, quero ok=%v", tt.password, err, tt.ok)
		}
	}
}
