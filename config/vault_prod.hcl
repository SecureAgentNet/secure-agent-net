# HashiCorp Vault Production Configuration for SecureAgentNet
# Run: vault server -config=vault_prod.hcl

storage "raft" {
  path    = "/vault/data"
  node_id = "node1"

  retry_join {
    leader_api_addr = "http://vault:8200"
  }
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = false
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file  = "/vault/certs/vault.key"
}

api_addr      = "https://vault:8200"
cluster_addr  = "https://vault:8201"
ui            = true
disable_mlock = false

# Audit device — logs all requests
audit {
  type       = "file"
  path       = "vault_audit.log"
  log_raw    = true
}

# Transit engine for HMAC audit signing
# Enable after unseal:
#   vault secrets enable transit
#   vault write -f transit/keys/audit-log-key type=hmac

# Dynamic secrets for agent credential injection
#   vault secrets enable -path=agents kv-v2
#   vault kv put agents/my-agent API_KEY=sk-xxx DB_PASS=xxx
