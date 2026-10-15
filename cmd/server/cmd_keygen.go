package main

import (
	"fmt"
	"os"

	"github.com/heschaefer/envmem/internal/vault"
)

// cmdKeygen gera uma chave-mestra nova e a imprime em base64, uma única vez.
// O servidor nunca grava a chave: quem a guarda é o operador.
func cmdKeygen() {
	key := vault.GenerateKey()
	defer clear(key)

	// A chave vai sozinha para o stdout e o aviso para o stderr, para que a
	// saída possa ir direto para onde o operador guarda a chave.
	fmt.Println(vault.EncodeKey(key))
	fmt.Fprintln(os.Stderr, "Chave-mestra gerada. Guarde-a em local seguro: ela não é gravada em lugar nenhum")
	fmt.Fprintln(os.Stderr, "e, sem ela, os segredos do cofre não podem ser decifrados.")
}
