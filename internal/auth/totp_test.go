package auth

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfcSecret é o segredo dos vetores de teste das RFCs 4226 e 6238 (SHA-1).
var rfcSecret = []byte("12345678901234567890")

// Vetores do apêndice D da RFC 4226 (HOTP, 6 dígitos).
func TestHOTPRFC4226(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, w := range want {
		if got := hotp(rfcSecret, uint64(counter), 6); got != w {
			t.Errorf("contador %d: %s, quero %s", counter, got, w)
		}
	}
}

// Vetores do apêndice B da RFC 6238 (TOTP com SHA-1). A RFC usa 8 dígitos;
// com 6, o código são os 6 últimos.
func TestTOTPRFC6238(t *testing.T) {
	tests := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, tt := range tests {
		at := time.Unix(tt.unix, 0)
		if got := hotp(rfcSecret, uint64(TOTPStep(at)), 8); got != tt.want {
			t.Errorf("T=%d: %s, quero %s", tt.unix, got, tt.want)
		}
		if got := TOTPCode(rfcSecret, at); got != tt.want[2:] {
			t.Errorf("T=%d, 6 dígitos: %s, quero %s", tt.unix, got, tt.want[2:])
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	now := time.Unix(1111111111, 0)
	step := TOTPStep(now)
	code := func(offset int64) string { return hotp(rfcSecret, uint64(step+offset), totpDigits) }

	// O passo atual e os vizinhos valem; dois passos de distância, não.
	for _, off := range []int64{-1, 0, 1} {
		if got, ok := VerifyTOTP(rfcSecret, code(off), now, 0); !ok || got != step+off {
			t.Errorf("passo %+d: %d, %v; quero aceito no passo %d", off, got, ok, step+off)
		}
	}
	for _, off := range []int64{-2, 2} {
		if _, ok := VerifyTOTP(rfcSecret, code(off), now, 0); ok {
			t.Errorf("passo %+d: aceito, quero recusado", off)
		}
	}

	// Reuso: depois de aceito no passo atual, o mesmo código (e os de
	// passos anteriores) são recusados; o do passo seguinte ainda vale.
	if _, ok := VerifyTOTP(rfcSecret, code(0), now, step); ok {
		t.Error("o mesmo código foi aceito duas vezes")
	}
	if _, ok := VerifyTOTP(rfcSecret, code(-1), now, step); ok {
		t.Error("um código anterior ao último usado foi aceito")
	}
	if got, ok := VerifyTOTP(rfcSecret, code(1), now, step); !ok || got != step+1 {
		t.Errorf("o código do passo seguinte: %d, %v", got, ok)
	}

	// Formato errado e segredo errado.
	for _, c := range []string{"", "12345", "1234567", "abcdef", code(0) + " "} {
		if _, ok := VerifyTOTP(rfcSecret, c, now, 0); ok {
			t.Errorf("código %q aceito", c)
		}
	}
	if _, ok := VerifyTOTP([]byte("outro segredo qualquer"), code(0), now, 0); ok {
		t.Error("código de outro segredo aceito")
	}
}

func TestNewTOTPSecret(t *testing.T) {
	a, b := NewTOTPSecret(), NewTOTPSecret()
	if len(a) != TOTPSecretSize || string(a) == string(b) {
		t.Fatalf("segredos: %x e %x", a, b)
	}
	// Base32 sem "=": 20 bytes viram 32 caracteres.
	if enc := EncodeTOTPSecret(a); len(enc) != 32 || strings.Contains(enc, "=") {
		t.Errorf("EncodeTOTPSecret = %q", enc)
	}
}

func TestTOTPURI(t *testing.T) {
	u, err := url.Parse(TOTPURI("ana@empresa.com", rfcSecret))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/envmem:ana@empresa.com" {
		t.Errorf("URI = %s", u)
	}
	want := map[string]string{"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer": "envmem", "algorithm": "SHA1", "digits": "6", "period": "30"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, quero %q", k, q.Get(k), v)
		}
	}
}
