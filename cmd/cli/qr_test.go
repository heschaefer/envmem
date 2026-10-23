package main

import (
	"strings"
	"testing"

	"rsc.io/qr"
)

// O desenho tem de reproduzir exatamente os módulos do QR: refaz a matriz
// a partir dos caracteres e compara com a do rsc.io/qr.
func TestWriteQR(t *testing.T) {
	const uri = "otpauth://totp/envmem:ana@empresa.com?algorithm=SHA1&digits=6&issuer=envmem&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	var b strings.Builder
	if err := writeQR(&b, uri); err != nil {
		t.Fatal(err)
	}
	code, err := qr.Encode(uri, qr.L)
	if err != nil {
		t.Fatal(err)
	}
	side := code.Size + 2*qrQuietZone
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if want := (side + 1) / 2; len(lines) != want {
		t.Fatalf("%d linhas, quero %d", len(lines), want)
	}
	for row, line := range lines {
		if !strings.HasPrefix(line, qrColors) || !strings.HasSuffix(line, qrReset) {
			t.Fatalf("linha %d sem as cores forçadas: %q", row, line)
		}
		cells := []rune(strings.TrimSuffix(strings.TrimPrefix(line, qrColors), qrReset))
		if len(cells) != side {
			t.Fatalf("linha %d com %d colunas, quero %d", row, len(cells), side)
		}
		for x, c := range cells {
			top := c == '█' || c == '▀'
			bottom := c == '█' || c == '▄'
			for i, got := range []bool{top, bottom} {
				y := 2*row + i
				want := false
				if mx, my := x-qrQuietZone, y-qrQuietZone; mx >= 0 && my >= 0 && mx < code.Size && my < code.Size {
					want = code.Black(mx, my)
				}
				if got != want {
					t.Fatalf("módulo (%d, %d) = %v, quero %v", x, y, got, want)
				}
			}
		}
	}
}
