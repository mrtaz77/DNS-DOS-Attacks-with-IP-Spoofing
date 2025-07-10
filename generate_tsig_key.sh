#!/usr/bin/env bash
set -e

KEY_NAME="tsig-key-$(date +%s)"
KEY_DIR="dns_server/keys"
mkdir -p "$KEY_DIR"
KEY_FILE="$KEY_DIR/${KEY_NAME}.key"
ALG="HMAC-SHA256"

# Ensure dnssec-keygen is available
if ! command -v dnssec-keygen &>/dev/null; then
  echo "dnssec-keygen not found. Please install bind9utils or bind-utils."
  exit 1
fi

# Test and generate TSIG key or fallback to OpenSSL
if command -v dnssec-keygen &>/dev/null && dnssec-keygen -a "${ALG}" -b 256 -n USER testkey &>/dev/null; then
  # use dnssec-keygen to generate TSIG key
  KFILE=$(dnssec-keygen -a "${ALG}" -b 256 -n USER "${KEY_NAME}")
  KEY_NAME_OUT=$(grep '^KeyName:' ${KFILE}.private | cut -d '"' -f2)
  SECRET=$(grep '^Secret:'  ${KFILE}.private | cut -d '"' -f2)
  # cleanup generated files
  rm -f Ktestkey+*.* K${KEY_NAME}*.*
else
  echo "⚠️ dnssec-keygen unsupported or algorithm not supported; generating secret with OpenSSL"
  KEY_NAME_OUT="${KEY_NAME}"
  # generate a 32-byte base64 secret
  if command -v openssl &>/dev/null; then
    SECRET=$(openssl rand -base64 32)
  else
    echo "Error: openssl not available to generate secret"
    exit 1
  fi
fi

# Write out a .key file in the standard TSIG format
cat > "${KEY_FILE}" <<EOF
# TSIG key: ${KEY_NAME_OUT}
${KEY_NAME_OUT}    ${ALG}    ${SECRET}
EOF

echo "✅ Generated TSIG key in ${KEY_FILE}:"
echo "   Key name: ${KEY_NAME_OUT}"
echo "   Algorithm: ${ALG}"
echo "   Secret:    ${SECRET}"
