#!/bin/bash
# ==============================================================================
# AAYOG_CHUNAV 2.0 - PKI & Certificate Generation Script
# Generates:
#   1. Root Certificate Authority (ca.crt, ca.key)
#   2. Server TLS Certificate with SAN (server.crt, server.key)
#   3. Admin Client Certificate for mTLS (admin_client.crt, admin_client.key)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$PROJECT_ROOT/certs"

OPENSSL_BIN="/opt/homebrew/bin/openssl"
if [ ! -x "$OPENSSL_BIN" ]; then
    OPENSSL_BIN="/usr/bin/openssl"
fi
if [ ! -x "$OPENSSL_BIN" ]; then
    OPENSSL_BIN="openssl"
fi

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[1/3] Generating Root Certificate Authority (CA)..."
"$OPENSSL_BIN" genrsa -out ca.key 2048
"$OPENSSL_BIN" req -x509 -new -nodes -key ca.key -sha256 -days 365 \
    -subj "/C=IN/ST=Delhi/L=New Delhi/O=Election Commission of India/OU=AAYOG_CHUNAV Root CA/CN=AAYOG-Root-CA" \
    -out ca.crt

echo "[2/3] Generating Server Certificate with SAN (localhost, 127.0.0.1)..."
"$OPENSSL_BIN" genrsa -out server.key 2048
"$OPENSSL_BIN" req -new -key server.key \
    -subj "/C=IN/ST=Delhi/L=New Delhi/O=AAYOG_CHUNAV Server/CN=localhost" \
    -out server.csr

cat << 'EOF' > server_ext.cnf
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

"$OPENSSL_BIN" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile server_ext.cnf

echo "[3/3] Generating Admin Client Certificate for Mutual TLS (mTLS)..."
"$OPENSSL_BIN" genrsa -out admin_client.key 2048
"$OPENSSL_BIN" req -new -key admin_client.key \
    -subj "/C=IN/ST=Delhi/L=New Delhi/O=AAYOG_CHUNAV Election Office/OU=Election Admin/CN=Chief Election Officer" \
    -out admin_client.csr

cat << 'EOF' > client_ext.cnf
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

"$OPENSSL_BIN" x509 -req -in admin_client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out admin_client.crt -days 365 -sha256 -extfile client_ext.cnf

rm -f server.csr server_ext.cnf admin_client.csr client_ext.cnf ca.srl

chmod 600 ca.key server.key admin_client.key
chmod 644 ca.crt server.crt admin_client.crt

echo "[SUCCESS] All certificates generated successfully in $CERT_DIR"
