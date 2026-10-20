#!/bin/sh
# Gera a CA própria do envmem e o certificado do servidor assinado por ela.
#
# Uso: scripts/gen-certs.sh [diretório]     (padrão: certs)
#
# Arquivos gerados:
#   ca.crt      certificado da CA. Vai para os clientes (envmem --ca), que
#               só aceitam servidores assinados por ela.
#   ca.key      chave privada da CA. Quem a tem consegue emitir um
#               certificado válido e se passar pelo servidor. Fora do
#               ambiente de desenvolvimento, deve ficar fora do servidor.
#   server.crt  certificado do servidor, assinado pela CA.
#   server.key  chave privada do servidor. Só o envmem-server a lê.
#
# Os nomes em que o certificado do servidor vale (SAN) podem ser trocados
# pela variável ENVMEM_CERT_SANS, no formato do openssl, por exemplo:
#   ENVMEM_CERT_SANS="DNS:envmem.empresa.local,IP:10.0.0.5" scripts/gen-certs.sh
set -eu

dir="${1:-certs}"
sans="${ENVMEM_CERT_SANS:-DNS:localhost,IP:127.0.0.1,IP:::1}"

if [ -e "$dir/ca.key" ] || [ -e "$dir/server.key" ]; then
    echo "gen-certs: $dir já tem chaves; apague o diretório para gerar de novo" >&2
    exit 1
fi

# umask 077: o diretório nasce com 700 e as chaves privadas com 600.
umask 077
mkdir -p "$dir"

# Curva P-256 (ECDSA): chaves curtas, assinatura rápida, aceita por todo
# cliente TLS 1.3.
#
# CA: pode assinar certificados (CA:TRUE), mas não outras CAs (pathlen:0).
# Validade de 5 anos.
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout "$dir/ca.key" -out "$dir/ca.crt" -days 1825 \
    -subj "/CN=envmem CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    2>/dev/null

# Servidor: assinado pela CA (-CA/-CAkey), só para autenticar servidor TLS
# (serverAuth), sem poder assinar outros certificados (CA:FALSE). O cliente
# confere o nome do servidor no SAN, não no CN. Validade de 1 ano.
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout "$dir/server.key" -out "$dir/server.crt" -days 365 \
    -subj "/CN=envmem-server" \
    -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -addext "subjectAltName=$sans" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    2>/dev/null

# Certificados são públicos; as chaves continuam com 600.
chmod 644 "$dir/ca.crt" "$dir/server.crt"

openssl verify -CAfile "$dir/ca.crt" "$dir/server.crt" >/dev/null
echo "gen-certs: certificados em $dir/ (SAN: $sans)"
