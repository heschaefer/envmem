package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert grava em dir um certificado autoassinado para 127.0.0.1 e
// a chave dele, e devolve os caminhos e o certificado (para o cliente
// confiar nele).
func writeTestCert(t *testing.T, dir string) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "teste"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	cert, _ = x509.ParseCertificate(der)
	return certFile, keyFile, cert
}

func TestServerTLSOnlyAcceptsTLS13(t *testing.T) {
	certFile, keyFile, cert := writeTestCert(t, t.TempDir())
	cfg, err := ServerTLS(certFile, keyFile)
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	dial := func(maxVersion uint16) (*tls.Conn, error) {
		return tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, MaxVersion: maxVersion})
	}

	conn, err := dial(0) // sem limite: negocia a maior versão em comum
	if err != nil {
		t.Fatalf("handshake TLS 1.3: %v", err)
	}
	if v := conn.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Errorf("versão negociada = %s, quero TLS 1.3", tls.VersionName(v))
	}
	conn.Close()

	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS11} {
		if conn, err := dial(v); err == nil {
			conn.Close()
			t.Errorf("cliente com no máximo %s foi aceito", tls.VersionName(v))
		}
	}
}

func TestServerTLSMissingFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := ServerTLS(filepath.Join(dir, "nao.crt"), filepath.Join(dir, "nao.key")); err == nil {
		t.Fatal("esperava erro com arquivos inexistentes")
	}
}
