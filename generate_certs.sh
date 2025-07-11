#!/bin/bash
set -e
CERT_DIR="dns_server/certs"
mkdir -p "$CERT_DIR"

# Generate private key
openssl genrsa -out "$CERT_DIR/key.pem" 2048

# Generate self-signed certificate
openssl req -new -x509 -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -days 3650 -subj "/C=US/ST=State/L=City/O=Org/OU=Unit/CN=example.com"
echo "Generated cert.pem and key.pem in $CERT_DIR"
