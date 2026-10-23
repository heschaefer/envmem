package main

import (
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"rsc.io/qr"
)

// qrQuietZone é a margem branca em volta do QR, em módulos: 4, o mínimo da
// especificação. Sem ela, o leitor do celular não acha as bordas.
const qrQuietZone = 4

// Cores ANSI forçadas: módulos pretos sobre fundo branco, nos temas claro e
// escuro do terminal. Em terminal escuro, um QR "claro sobre escuro" sairia
// invertido, e nem todo leitor de QR aceita.
const (
	qrColors = "\x1b[30;107m" // texto preto, fundo branco brilhante
	qrReset  = "\x1b[0m"
)

// canShowQR diz se dá para desenhar o QR no stderr: precisa ser um terminal
// que entenda cores (no modo TERM=dumb, só a chave em texto aparece).
func canShowQR() bool {
	return term.IsTerminal(int(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
}

// writeQR desenha text como QR code em w. Cada caractere mostra dois
// módulos, um em cima do outro (os caracteres do terminal são cerca de duas
// vezes mais altos que largos): assim o QR sai quadrado e com metade das
// linhas.
func writeQR(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return err
	}
	// black diz se o módulo (x, y) é preto, contando a margem; fora do
	// código, é margem (branco).
	black := func(x, y int) bool {
		x, y = x-qrQuietZone, y-qrQuietZone
		return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
	}
	side := code.Size + 2*qrQuietZone
	var b strings.Builder
	for y := 0; y < side; y += 2 {
		b.WriteString(qrColors)
		for x := 0; x < side; x++ {
			top, bottom := black(x, y), black(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString(qrReset + "\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
