#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    if [ $? -ne 0 ]; then
        echo ""
        log_error "Setup failed. Check output above for details."
    fi
}
trap cleanup EXIT

echo ""
echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}  SecureAgentNet - Development Setup    ${NC}"
echo -e "${CYAN}=========================================${NC}"
echo ""

# ------------------------------------------------------------------
# Prerequisites
# ------------------------------------------------------------------
log_info "Checking prerequisites..."

command -v docker >/dev/null 2>&1 || { log_error "docker is required but not installed."; exit 1; }
log_ok "docker found: $(docker --version)"

command -v python3 >/dev/null 2>&1 || { log_error "python3 is required but not installed."; exit 1; }
log_ok "python3 found: $(python3 --version)"

command -v pip3 >/dev/null 2>&1 || { log_error "pip3 is required but not installed."; exit 1; }
log_ok "pip3 found: $(pip3 --version 2>&1 | cut -d' ' -f1-2)"

# ------------------------------------------------------------------
# Python virtual environment
# ------------------------------------------------------------------
log_info "Setting up Python virtual environment..."

if [ -d "$PROJECT_DIR/venv" ]; then
    log_warn "Virtual environment already exists at venv/. Skipping creation."
else
    python3 -m venv "$PROJECT_DIR/venv"
    log_ok "Virtual environment created."
fi

source "$PROJECT_DIR/venv/bin/activate"
log_ok "Virtual environment activated."

# ------------------------------------------------------------------
# Install Python dependencies
# ------------------------------------------------------------------
log_info "Installing Python requirements..."

pip install --upgrade pip -q
pip install -r "$PROJECT_DIR/requirements.txt" -q
pip install -r "$PROJECT_DIR/requirements-dev.txt" -q
log_ok "Python packages installed."

# ------------------------------------------------------------------
# Docker infrastructure (Postgres, Vault, Redis, Ollama)
# ------------------------------------------------------------------
log_info "Starting infrastructure services with Docker Compose..."

cd "$PROJECT_DIR/deployment"

docker compose -f docker-compose.yml up -d postgres vault redis ollama
log_ok "Infrastructure services started."

# ------------------------------------------------------------------
# Wait for database to be healthy
# ------------------------------------------------------------------
log_info "Waiting for PostgreSQL to become healthy..."
for i in $(seq 1 30); do
    if docker exec securenet-postgres pg_isready -U secureagent -d securenet_db >/dev/null 2>&1; then
        log_ok "PostgreSQL is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        log_error "PostgreSQL did not become ready in time."
        exit 1
    fi
    sleep 2
done

# ------------------------------------------------------------------
# Run database migrations
# ------------------------------------------------------------------
log_info "Running database migrations..."

python3 "$PROJECT_DIR/scripts/init_database.py"
log_ok "Database initialization complete."

# ------------------------------------------------------------------
# Seed test data
# ------------------------------------------------------------------
log_info "Seeding test data..."

python3 "$PROJECT_DIR/scripts/seed_test_data.py"
log_ok "Test data seeded."

# ------------------------------------------------------------------
# Build and start the application
# ------------------------------------------------------------------
log_info "Building and starting the application service..."

docker compose -f docker-compose.yml up -d app
log_ok "Application service started."

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  SecureAgentNet setup complete!        ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "  Dashboard:     ${CYAN}http://localhost:5000${NC}"
echo -e "  MCP Gateway:   ${CYAN}https://localhost:8443${NC}"
echo -e "  Vault UI:      ${CYAN}http://localhost:8200${NC}  (token: root)"
echo -e "  Ollama API:    ${CYAN}http://localhost:11434${NC}"
echo ""
echo -e "  Run ${YELLOW}source venv/bin/activate${NC} to use the Python env."
echo ""

cd "$PROJECT_DIR"
