# SecureAgentNet Production Deployment

## Prerequisites

- Docker 24+ with Docker Compose
- Linux host with AppArmor (optional, recommended)
- PostgreSQL 14+ (or use docker-compose)
- HashiCorp Vault (or use docker-compose)
- Ollama (or use docker-compose)
- Redis 7+ (or use docker-compose)

## Quick Deploy

```bash
# 1. Clone and enter
git clone https://github.com/SecureAgentNet/secure-agent-net
cd secure-agent-net

# 2. Run hardening script
sudo bash scripts/harden.sh

# 3. Set PostgreSQL password
export POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")

# 4. Start production stack
docker compose -f deployment/docker-compose.prod.yml up -d

# 5. Verify
secureagentnet doctor
```

## Manual Configuration

### Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `SECRET_KEY` | JWT signing key (min 32 chars) | Yes |
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `VAULT_ADDR` | HashiCorp Vault API URL | Yes |
| `VAULT_TOKEN` | Vault authentication token | Yes |
| `POSTGRES_PASSWORD` | PostgreSQL superuser password | Yes |
| `REDIS_PASSWORD` | Redis auth password | Yes |
| `OLLAMA_MODEL` | LLM model for semantic evaluation | No (defaults to llama3.2) |
| `CORS_ORIGINS` | Allowed CORS origins (comma-separated) | No (defaults to localhost) |
| `HITL_LOW_THRESHOLD` | Low threshold for HITL escalation (0.0-1.0) | No (defaults 0.3) |
| `HITL_HIGH_THRESHOLD` | High threshold for HITL escalation (0.0-1.0) | No (defaults 0.7) |

### Security Checklist

- [ ] Generate a strong `SECRET_KEY` (32+ bytes, never commit to git)
- [ ] Use TLS for all service-to-service communication in production
- [ ] Mount Docker socket read-only (`:ro`) when possible
- [ ] Enable AppArmor on the host and load `config/apparmor_profile`
- [ ] Enable Vault transit engine: `vault secrets enable transit`
- [ ] Configure Vault audit device for compliance
- [ ] Set up PostgreSQL with SSL/TLS connections
- [ ] Use Redis with `requirepass` in production
- [ ] Restrict CORS origins to known domains
- [ ] Run containers with `--read-only` rootfs
- [ ] Enable seccomp profiles per agent capability
- [ ] Set resource limits on all containers

### Validation

```bash
# System health
secureagentnet doctor

# Test pipeline with a benign action
secureagentnet agent register prod-test --capabilities execute_code
secureagentnet run prod-test "echo 'production test'"

# Test that malicious actions are blocked
secureagentnet run prod-test "rm -rf /" --intent "Delete everything"

# Check forensic audit trail
secureagentnet forensics query --agent prod-test
secureagentnet audit

# Verify Vault logging
curl -s http://localhost:8200/v1/sys/health | python3 -m json.tool
```

### Architecture

```
                    ┌──────────────┐
                    │   Operator   │
                    └──────┬───────┘
                           │
              ┌────────────▼───────────┐
              │  FastAPI Gateway (:5000)│
              │  + Flask Dashboard      │
              │  + MCP Protocol (:8443) │
              └─────┬──────────────────┘
                    │
     ┌──────────────┼──────────────┐
     ▼              ▼              ▼
┌─────────┐  ┌──────────┐  ┌──────────┐
│PostgreSQL│  │  Vault   │  │  Redis   │
│ :5432   │  │  :8200   │  │  :6379   │
└─────────┘  └──────────┘  └──────────┘
     │              │
     ▼              ▼
┌─────────┐  ┌──────────┐
│ Ollama  │  │  Docker  │
│ :11434  │  │  Sandbox │
└─────────┘  └──────────┘
```
