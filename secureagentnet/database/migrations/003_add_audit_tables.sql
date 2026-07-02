-- Migration 003: Audit & Reasoning Tables
-- Applied for full forensic capability

BEGIN;

CREATE TABLE audit_log_index (
    log_id BIGSERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    phase pipeline_phase,
    severity event_severity DEFAULT 'INFO',
    vault_path TEXT,
    correlation_id UUID,
    search_vector TSVECTOR,
    summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log_index(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log_index(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_phase ON audit_log_index(phase, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_log_index(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_search ON audit_log_index USING GIN(search_vector);

CREATE TABLE reasoning_logs (
    log_id BIGSERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    input_prompt TEXT,
    reasoning_steps TEXT,
    final_decision TEXT,
    confidence_score DECIMAL(5,4),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reasoning_agent ON reasoning_logs(agent_id, created_at DESC);

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    action_type policy_action NOT NULL DEFAULT 'deny',
    conditions JSONB NOT NULL DEFAULT '{}',
    priority INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE kill_switch_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    armed BOOLEAN DEFAULT TRUE,
    active BOOLEAN DEFAULT FALSE,
    trigger_count INT DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    last_reset_at TIMESTAMPTZ,
    reset_by VARCHAR(255)
);

INSERT INTO kill_switch_state (id, armed, active) VALUES (1, TRUE, FALSE)
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION update_search_vector()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector := to_tsvector('english', COALESCE(NEW.summary, ''));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_search_update ON audit_log_index;
CREATE TRIGGER trg_audit_search_update
BEFORE INSERT OR UPDATE ON audit_log_index
FOR EACH ROW EXECUTE FUNCTION update_search_vector();

COMMIT;
