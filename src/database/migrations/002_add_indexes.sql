-- Migration 002: Performance Indexes
-- Applied after initial schema

BEGIN;

CREATE INDEX IF NOT EXISTS idx_agent_type ON agents(type);
CREATE INDEX IF NOT EXISTS idx_agent_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agent_trust ON agents(trust_score DESC);
CREATE INDEX IF NOT EXISTS idx_cap_agent ON agent_capabilities(agent_id);
CREATE INDEX IF NOT EXISTS idx_auth_agent ON auth_events(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_auth_timestamp ON auth_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_container_agent ON containers(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_container_status ON containers(status);
CREATE INDEX IF NOT EXISTS idx_decision_agent ON decision_log(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_decision_result ON decision_log(final_decision, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_intent_user ON intent_capsules(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intent_expiry ON intent_capsules(expires_at) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

COMMIT;
