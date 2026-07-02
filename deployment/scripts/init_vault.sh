#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$PROJECT_DIR/.env"

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
echo -e "${CYAN}   SecureAgentNet - HashiCorp Vault Initializer   ${NC}"
echo -e "${CYAN}==================================================${NC}"
echo ""

# Check if vault container is running
if ! docker ps --filter "name=securenet-vault" --format "{{.Status}}" | grep -q "Up"; then
    log_error "securenet-vault container is not running. Please start it first: docker compose up -d vault"
    exit 1
fi

log_info "Waiting for Vault API to become responsive..."
for i in $(seq 1 10); do
    if docker exec securenet-vault vault status 2>&1 | grep -q "Initialized"; then
        break
    fi
    sleep 2
    if [ "$i" -eq 10 ]; then
        log_error "Vault container is running but API is not responding."
        exit 1
    fi
done

# Check if Vault is already initialized
INIT_STATUS=$(docker exec securenet-vault vault status -format=json | grep -o '"initialized":[^,]*' | cut -d: -f2 | tr -d ' ' || echo "false")

if [ "$INIT_STATUS" = "true" ]; then
    log_info "Vault is already initialized."
else
    log_info "Initializing Vault with 1 key share and threshold 1 for testing..."
    INIT_OUT=$(docker exec securenet-vault vault operator init -key-shares=1 -key-threshold=1 -format=json)
    
    # Extract keys and token
    UNSEAL_KEY=$(echo "$INIT_OUT" | grep -o '"unseal_keys_b64":[^]]*' | cut -d'[' -f2 | tr -d '"' | tr -d ' ' | cut -d',' -f1)
    ROOT_TOKEN=$(echo "$INIT_OUT" | grep -o '"root_token":[^,]*' | cut -d':' -f2 | tr -d '"' | tr -d ' ' | tr -d '}')
    
    # Save keys locally (secured)
    KEYS_FILE="$PROJECT_DIR/deployment/vault_keys.txt"
    echo "Unseal Key: $UNSEAL_KEY" > "$KEYS_FILE"
    echo "Root Token: $ROOT_TOKEN" >> "$KEYS_FILE"
    chmod 600 "$KEYS_FILE"
    
    log_ok "Vault initialized. Keys written to: $KEYS_FILE"
    log_warn "SAVE THESE KEYS SECURELY AND DELETE THE FILE IN PRODUCTION!"
fi

# Retrieve unseal key from keys file
KEYS_FILE="$PROJECT_DIR/deployment/vault_keys.txt"
if [ ! -f "$KEYS_FILE" ]; then
    log_error "vault_keys.txt not found at $KEYS_FILE. Cannot unseal Vault."
    exit 1
fi

UNSEAL_KEY=$(grep "Unseal Key:" "$KEYS_FILE" | cut -d':' -f2 | tr -d ' ')
ROOT_TOKEN=$(grep "Root Token:" "$KEYS_FILE" | cut -d':' -f2 | tr -d ' ')

# Unseal Vault if it is sealed
SEAL_STATUS=$(docker exec securenet-vault vault status -format=json | grep -o '"sealed":[^,]*' | cut -d: -f2 | tr -d ' ' || echo "true")
if [ "$SEAL_STATUS" = "true" ]; then
    log_info "Unsealing Vault..."
    docker exec securenet-vault vault operator unseal "$UNSEAL_KEY" >/dev/null
    log_ok "Vault unsealed."
else
    log_info "Vault is already unsealed."
fi

# Configure Vault secrets engines
log_info "Configuring Vault secrets engines using root token..."

# Login inside container
docker exec securenet-vault vault login "$ROOT_TOKEN" >/dev/null

# Enable Transit engine for secure audit logging
if ! docker exec securenet-vault vault secrets list | grep -q "transit/"; then
    docker exec securenet-vault vault secrets enable transit >/dev/null
    log_ok "Transit secrets engine enabled."
else
    log_info "Transit secrets engine already enabled."
fi

# Generate audit log signing key
if ! docker exec securenet-vault vault read transit/keys/audit-log-key >/dev/null 2>&1; then
    docker exec securenet-vault vault write -f transit/keys/audit-log-key type=hmac >/dev/null
    log_ok "Audit log HMAC key created."
else
    log_info "Audit log HMAC key already exists."
fi

# Enable Kv-v2 secrets engine for agent credentials
if ! docker exec securenet-vault vault secrets list | grep -q "agents/"; then
    docker exec securenet-vault vault secrets enable -path=agents kv-v2 >/dev/null
    log_ok "Agents KV-v2 secrets engine enabled."
else
    log_info "Agents KV-v2 secrets engine already enabled."
fi

# Update .env file with the root token
if [ -f "$ENV_FILE" ]; then
    if grep -q "VAULT_TOKEN=" "$ENV_FILE"; then
        # Replace existing VAULT_TOKEN line
        sed -i "s/VAULT_TOKEN=.*/VAULT_TOKEN=$ROOT_TOKEN/" "$ENV_FILE"
    else
        echo "VAULT_TOKEN=$ROOT_TOKEN" >> "$ENV_FILE"
    fi
    log_ok "Updated root token in $ENV_FILE"
fi

echo ""
echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}   Vault Initialized & Unsealed Successfully!     ${NC}"
echo -e "${GREEN}==================================================${NC}"
echo ""
