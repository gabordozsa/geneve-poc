#!/usr/bin/env bash
# gen-certs.sh — generate a self-signed CA and a server certificate for
#                testing preprocess with -L (local TLS) and/or -R (remote TLS).
#
# Output (written to ./certs/ relative to the project root):
#   certs/ca.key        CA private key
#   certs/ca.crt        Self-signed CA certificate
#   certs/server.key    Server private key
#   certs/server.csr    Server certificate signing request
#   certs/server.crt    Server certificate signed by the local CA
#
# Usage:
#   ./scripts/gen-certs.sh            # defaults: CN=localhost, 825-day validity
#   CN=192.168.1.10 ./scripts/gen-certs.sh
#
# The paths certs/server.crt and certs/server.key are the defaults compiled
# into preprocess.c (SERVER_CERT / SERVER_KEY macros).  Override at build
# time with:
#   gcc ... -DSERVER_CERT=\"/path/to/cert.pem\" -DSERVER_KEY=\"/path/to/key.pem\"

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
CN="${CN:-localhost}"           # Common Name / SAN for the server certificate
DAYS="${DAYS:-825}"             # Validity period in days
BITS="${BITS:-2048}"            # RSA key size
OUT_DIR="${OUT_DIR:-certs}"     # Output directory (relative to CWD)

# ---------------------------------------------------------------------------
# Sanity check
# ---------------------------------------------------------------------------
if ! command -v openssl &>/dev/null; then
    echo "error: openssl not found in PATH" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

echo "==> Generating certificates in ./$OUT_DIR  (CN=$CN, days=$DAYS, bits=$BITS)"

# ---------------------------------------------------------------------------
# 1. CA key + self-signed certificate
# ---------------------------------------------------------------------------
echo ""
echo "[1/4] Generating CA private key ..."
openssl genrsa -out "$OUT_DIR/ca.key" "$BITS" 2>/dev/null

echo "[2/4] Generating self-signed CA certificate ..."
openssl req -new -x509 \
    -key    "$OUT_DIR/ca.key" \
    -out    "$OUT_DIR/ca.crt" \
    -days   "$DAYS" \
    -subj   "/CN=Preprocess-Test-CA/O=preprocess/OU=testing" \
    2>/dev/null

# ---------------------------------------------------------------------------
# 2. Server key + CSR
# ---------------------------------------------------------------------------
echo "[3/4] Generating server key and CSR ..."
openssl genrsa -out "$OUT_DIR/server.key" "$BITS" 2>/dev/null

# Build a minimal OpenSSL config that adds a SAN so modern TLS stacks
# (Chrome, curl, Go) accept the certificate without extra flags.
TMP_CNF="$(mktemp /tmp/gen-certs-XXXXXX.cnf)"
trap 'rm -f "$TMP_CNF"' EXIT

cat > "$TMP_CNF" <<EOF
[req]
distinguished_name = dn
req_extensions     = req_ext
prompt             = no

[dn]
CN = ${CN}
O  = preprocess
OU = testing

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${CN}
IP.1  = 127.0.0.1
EOF

# Add the CN as an IP SAN as well if it looks like an IP address
if [[ "$CN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.2  = ${CN}" >> "$TMP_CNF"
fi

openssl req -new \
    -key    "$OUT_DIR/server.key" \
    -out    "$OUT_DIR/server.csr" \
    -config "$TMP_CNF" \
    2>/dev/null

# ---------------------------------------------------------------------------
# 3. Sign the server CSR with the CA
# ---------------------------------------------------------------------------
echo "[4/4] Signing server certificate with CA ..."

# Extension config for signing (SAN must be re-specified at sign time)
TMP_EXT="$(mktemp /tmp/gen-certs-ext-XXXXXX.cnf)"
trap 'rm -f "$TMP_CNF" "$TMP_EXT"' EXIT

cat > "$TMP_EXT" <<EOF
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${CN}
IP.1  = 127.0.0.1
EOF
if [[ "$CN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.2  = ${CN}" >> "$TMP_EXT"
fi

openssl x509 -req \
    -in         "$OUT_DIR/server.csr" \
    -CA         "$OUT_DIR/ca.crt" \
    -CAkey      "$OUT_DIR/ca.key" \
    -CAcreateserial \
    -out        "$OUT_DIR/server.crt" \
    -days       "$DAYS" \
    -extfile    "$TMP_EXT" \
    2>/dev/null

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Done.  Files written to ./$OUT_DIR/:"
ls -1 "$OUT_DIR/"
echo ""
echo "Certificate details:"
openssl x509 -noout -subject -issuer -dates -ext subjectAltName \
    -in "$OUT_DIR/server.crt"
echo ""
echo "Quick-start:"
echo "  Build :  gcc -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2 -g \\"
echo "               src/preprocess.c -o preprocess -lssl -lcrypto"
echo ""
echo "  Local TLS only  (-L):  ./preprocess -l 8443 -r 127.0.0.1 -p 9000 -L"
echo "  Remote TLS only (-R):  ./preprocess -l 8080 -r 127.0.0.1 -p 443  -R"
echo "  Both sides      (-LR): ./preprocess -l 8443 -r 127.0.0.1 -p 443  -L -R"
echo ""
echo "  Test TLS local with openssl s_client:"
echo "    openssl s_client -connect 127.0.0.1:8443 -CAfile $OUT_DIR/ca.crt"
