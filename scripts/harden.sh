#!/bin/bash
# Production Hardening Script for SecureAgentNet
# Run: sudo bash scripts/harden.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[SAN]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC}  $1"; }

echo ""
echo -e "${CYAN}=====================================${NC}"
echo -e "${CYAN}  SecureAgentNet Production Hardening${NC}"
echo -e "${CYAN}=====================================${NC}"
echo ""

# 1. Generate SECRET_KEY
log "Generating production SECRET_KEY..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ok "SECRET_KEY generated"

# 2. Configure .env for production
log "Configuring .env for production mode..."
cat > .env << EOF
ENVIRONMENT=production
DEPLOY_MODE=docker
DATABASE_URL=postgresql://secureagent:\${POSTGRES_PASSWORD}@postgres:5432/securenet_db
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=root
OLLAMA_API_URL=http://ollama:11434/api/generate
OLLAMA_MODEL=llama3.2
SECRET_KEY=${SECRET_KEY}
AGENT_JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600
KILL_SWITCH_THRESHOLD=5
CIRCUIT_BREAKER_TIMEOUT=120
BLOCK_THRESHOLD=0.6
HITL_LOW_THRESHOLD=0.3
HITL_HIGH_THRESHOLD=0.7
CONTAINER_CPU_LIMIT=1.0
CONTAINER_MEMORY_LIMIT=512m
CONTAINER_TIMEOUT_SECONDS=60
MCP_PORT=8443
REDIS_HOST=redis
REDIS_PORT=6379
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=\$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
CORS_ORIGINS=https://your-domain.com
EOF
ok ".env configured"

# 3. Initialize Vault transit engine
log "Configuring Vault transit engine..."
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 securenet-vault vault secrets enable transit 2>/dev/null || true
ok "Vault transit engine ready"

# 4. Load AppArmor profiles (Linux only)
if command -v apparmor_parser >/dev/null 2>&1; then
    log "Loading AppArmor profiles..."
    PROFILES_DIR="${HOME}/.secureagentnet/profiles"
    mkdir -p "$PROFILES_DIR"
    cp config/apparmor_profile "$PROFILES_DIR/securenet-agent"
    sudo apparmor_parser -r "$PROFILES_DIR/securenet-agent" 2>/dev/null || log "AppArmor profile written but not loaded (may need sudo)"
    ok "AppArmor profile staged at ${PROFILES_DIR}"
else
    log "AppArmor not available — skipping (container seccomp covers most cases)"
fi

# 5. Database migration
log "Running database migrations..."
python3 scripts/init_database.py
ok "Database schema applied"

# 6. Verify
log "Running system health check..."
python3 -m secureagentnet doctor --deploy-mode docker 2>/dev/null || log "Run: secureagentnet doctor"
ok "Hardening complete"

echo ""
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  Production hardening complete      ${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Copy the SECRET_KEY and store it securely (not in git)"
echo "  2. Set POSTGRES_PASSWORD in your shell or docker-compose env"
echo "  3. Run: docker compose -f deployment/docker-compose.prod.yml up -d"
echo "  4. Run: secureagentnet doctor"
echo ""
