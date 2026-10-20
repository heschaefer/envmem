package config

import (
	"crypto/tls"
	"fmt"
)

// ServerTLS monta a configuração TLS do envmem-server com o certificado e a
// chave em PEM. Só aceita TLS 1.3: um cliente que ofereça só TLS 1.2 ou
// anterior é recusado já no handshake, antes de qualquer requisição.
//
// No TLS 1.3 não há suítes a escolher: as três do protocolo usam cifra
// autenticada (AES-GCM ou ChaCha20-Poly1305), e a troca de chaves é sempre
// efêmera (sigilo futuro: quem obtiver a chave do servidor depois não
// decifra o tráfego gravado antes). Por isso o Go ignora CipherSuites
// quando a versão é 1.3, e esta configuração não as lista.
func ServerTLS(certFile, keyFile string) (*tls.Config, error) {
	// Carregar aqui, e não no ListenAndServeTLS, faz o servidor falhar na
	// subida (com mensagem clara) se os arquivos estiverem errados.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("carregar certificado TLS (gere com scripts/gen-certs.sh): %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}, nil
}
