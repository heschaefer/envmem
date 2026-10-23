package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// TOTP (RFC 6238) é o código de 6 dígitos que muda a cada 30 segundos, o
// mesmo dos apps autenticadores (Google Authenticator, Authy, FreeOTP...).
// O app e o servidor guardam o mesmo segredo e calculam o código a partir
// dele e da hora atual; nada trafega entre os dois depois do cadastro.
//
// Os parâmetros são os únicos que todos os apps aceitam: HMAC-SHA1, 6
// dígitos e passos de 30 segundos. O SHA-1 aqui não é um problema: o
// HMAC-SHA1 continua seguro como função pseudoaleatória, e o que quebra no
// SHA-1 (achar colisões) não ajuda a adivinhar o código.

const (
	// TOTPSecretSize é o tamanho do segredo: 20 bytes (160 bits), o
	// recomendado pela RFC 4226 para o HMAC-SHA1.
	TOTPSecretSize = 20

	totpDigits = 6
	totpPeriod = 30 // segundos por passo

	// totpSkew é quantos passos antes e depois do atual são aceitos, para
	// tolerar relógio fora de sincronia e o tempo de digitar: com 1, um
	// código vale por até 90 segundos.
	totpSkew = 1

	// totpIssuer é o nome que o app autenticador mostra ao lado da conta.
	totpIssuer = "envmem"
)

// NewTOTPSecret gera um segredo novo com o crypto/rand.
func NewTOTPSecret() []byte {
	b := make([]byte, TOTPSecretSize)
	rand.Read(b)
	return b
}

// TOTPStep é o número do passo de 30 segundos em que t cai, contado desde
// 1970 (o "T" da RFC 6238).
func TOTPStep(t time.Time) int64 {
	return t.Unix() / totpPeriod
}

// hotp é o HOTP da RFC 4226: o código para um contador (no TOTP, o
// contador é o passo de tempo).
func hotp(secret []byte, counter uint64, digits int) string {
	// 1. HMAC-SHA1 do contador, em 8 bytes big-endian, com o segredo como
	// chave. O resultado tem 20 bytes.
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	// 2. Truncamento dinâmico: os 4 bits finais do último byte escolhem
	// onde começam os 4 bytes usados (de 0 a 15). O bit mais alto é
	// descartado (& 0x7fffffff) para o número nunca ser negativo.
	offset := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	// 3. Os últimos dígitos do número, com zeros à esquerda.
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, n%mod)
}

// TOTPCode é o código válido no instante t.
func TOTPCode(secret []byte, t time.Time) string {
	return hotp(secret, uint64(TOTPStep(t)), totpDigits)
}

// VerifyTOTP confere code no passo de t e nos vizinhos (totpSkew) e
// devolve o passo aceito. Passos até lastStep (o último já usado) são
// recusados: cada código vale uma vez, e quem viu o código na tela de
// alguém (ou o capturou) não consegue reutilizá-lo. O servidor guarda o
// passo devolvido como o novo lastStep.
func VerifyTOTP(secret []byte, code string, t time.Time, lastStep int64) (step int64, ok bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	now := TOTPStep(t)
	for s := now - totpSkew; s <= now+totpSkew; s++ {
		if s <= lastStep {
			continue
		}
		// Comparação em tempo constante: o tempo da resposta não revela
		// quantos dígitos estavam certos.
		if subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(s), totpDigits)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// EncodeTOTPSecret escreve o segredo em base32 sem "=", o formato que os
// apps aceitam para digitar a chave à mão.
func EncodeTOTPSecret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// TOTPURI é o link otpauth:// que vai no QR code do cadastro (formato
// "Key Uri Format", usado por todos os apps): nome da conta, segredo e
// parâmetros.
func TOTPURI(account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", EncodeTOTPSecret(secret))
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + totpIssuer + ":" + account,
		RawQuery: q.Encode(),
	}
	return u.String()
}
