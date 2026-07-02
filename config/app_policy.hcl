# SecureAgentNet Minimal Application Policy
# Defines the exact required capabilities for log signing, log verification,
# audit log persistence, and dynamic secret injection.

# Read transit key metadata (used by VaultAuditClient to verify key availability)
path "transit/keys/audit-log-key" {
  capabilities = ["read"]
}

# Sign logs using transit HMAC
path "transit/hmac/audit-log-key" {
  capabilities = ["update"]
}

# Verify signed logs
path "transit/verify/audit-log-key" {
  capabilities = ["update"]
}

# Write, read, and update agent audit logs in the agents KV mount
path "agents/data/audit/agents/*" {
  capabilities = ["create", "read", "update"]
}

# Read agent credentials in the default secret KV mount
path "secret/data/agents/*" {
  capabilities = ["read"]
}
