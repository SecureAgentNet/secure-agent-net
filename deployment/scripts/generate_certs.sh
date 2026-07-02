#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERTS_DIR="$PROJECT_DIR/deployment/certs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo -e "${CYAN}==================================================${NC}"
echo -e "${CYAN}   SecureAgentNet - TLS/SSL Cert Generator        ${NC}"
echo -e "${CYAN}==================================================${NC}"
echo ""

# Check for OpenSSL
if ! command -v openssl >/dev/null 2>&1; then
    log_error "openssl is required but not installed."
    exit 1
fi

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

log_info "Generating self-signed certificate for local/multi-host testing..."

# Generate private key and self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout securenet.key \
    -out securenet.crt \
    -subj "/C=US/ST=State/L=City/O=SecureAgentNet/OU=Security/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1" \
    2>/dev/null

# Secure key permissions
chmod 600 securenet.key
chmod 644 securenet.crt

log_ok "Certificates generated successfully in: $CERTS_DIR"
echo -e "  Private Key:   ${YELLOW}securenet.key${NC}"
echo -e "  Certificate:   ${YELLOW}securenet.crt${NC}"
echo ""
log_warn "These are self-signed certificates. Browsers/SDKs will show trust warnings unless SSL verification is skipped or the certificate is added to the system root store."
log_warn "For true production, mount valid Certbot / Let's Encrypt certificates instead."
echo ""
