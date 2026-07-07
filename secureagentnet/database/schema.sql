-- SecureAgentNet PostgreSQL Schema
-- ITCD Pipeline: Identify, Track, Contain, Decide

-- ===== ENUMS =====
DO $$ BEGIN
    CREATE TYPE agent_status AS ENUM ('pending', 'active', 'suspended', 'revoked', 'rogue');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE policy_action AS ENUM ('allow', 'deny', 'requires_approval');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE event_severity AS ENUM ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE pipeline_phase AS ENUM ('IDENTIFY', 'TRACK', 'CONTAIN', 'DECIDE');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE final_decision AS ENUM ('APPROVE', 'DENY', 'ESCALATE');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

-- ===== IDENTITY REGISTRY =====
CREATE TABLE IF NOT EXISTS agents (
    agent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL DEFAULT 'Custom',
    description TEXT,
    public_key TEXT,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ,
    trust_score DECIMAL(5,2) DEFAULT 50.00 CHECK (trust_score >= 0 AND trust_score <= 100),
    status agent_status DEFAULT 'pending',
    capabilities JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_by VARCHAR(255),
    CONSTRAINT unique_agent_name UNIQUE(name)
);

CREATE INDEX IF NOT EXISTS idx_agent_type ON agents(type);
CREATE INDEX IF NOT EXISTS idx_agent_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agent_trust ON agents(trust_score DESC);

-- ===== AGENT CAPABILITIES =====
CREATE TABLE IF NOT EXISTS agent_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(agent_id) ON DELETE CASCADE,
    capability_name VARCHAR(100) NOT NULL,
    capability_level INT DEFAULT 0 CHECK (capability_level >= 0 AND capability_level <= 4),
    is_allowed BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(agent_id, capability_name)
);

CREATE INDEX IF NOT EXISTS idx_cap_agent ON agent_capabilities(agent_id);

-- ===== POLICIES =====
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    action_type policy_action NOT NULL DEFAULT 'deny',
    conditions JSONB NOT NULL DEFAULT '{}',
    priority INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ===== AUTHENTICATION LOG =====
CREATE TABLE IF NOT EXISTS auth_events (
    event_id BIGSERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    challenge_nonce BYTEA,
    signature BYTEA,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    success BOOLEAN,
    failure_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_agent ON auth_events(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_auth_timestamp ON auth_events(timestamp DESC);

-- ===== AUDIT LOG INDEX =====
CREATE TABLE IF NOT EXISTS audit_log_index (
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

-- ===== REASONING LOGS =====
CREATE TABLE IF NOT EXISTS reasoning_logs (
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

-- ===== CONTAINER REGISTRY =====
CREATE TABLE IF NOT EXISTS containers (
    container_id VARCHAR(64) PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id) ON DELETE CASCADE,
    image VARCHAR(255) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('creating', 'running', 'stopped', 'failed', 'removed')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    stopped_at TIMESTAMPTZ,
    exit_code INT,
    cpu_limit DECIMAL(3,2),
    memory_limit_mb INT,
    network_mode VARCHAR(50),
    read_only_root BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_container_agent ON containers(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_container_status ON containers(status);

-- ===== DECISION LOG =====
CREATE TABLE IF NOT EXISTS decision_log (
    decision_id BIGSERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    request_hash BYTEA,
    tier1_result VARCHAR(10) CHECK (tier1_result IN ('PASS', 'DENY')),
    tier2_pii_count INT DEFAULT 0,
    tier2_entities JSONB,
    tier3_safe BOOLEAN,
    tier3_confidence DECIMAL(5,4),
    tier3_threats JSONB,
    tier3_reasoning TEXT,
    final_decision final_decision,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    processing_time_ms INT
);

CREATE INDEX IF NOT EXISTS idx_decision_agent ON decision_log(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_decision_result ON decision_log(final_decision, timestamp DESC);

-- ===== INTENT CAPSULES =====
CREATE TABLE IF NOT EXISTS intent_capsules (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(agent_id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    original_goal TEXT NOT NULL,
    approved_actions JSONB DEFAULT '[]',
    forbidden_actions JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_intent_user ON intent_capsules(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intent_expiry ON intent_capsules(expires_at) WHERE active = TRUE;

-- ===== KILL-SWITCH STATE =====
CREATE TABLE IF NOT EXISTS kill_switch_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    armed BOOLEAN DEFAULT TRUE,
    active BOOLEAN DEFAULT FALSE,
    trigger_count INT DEFAULT 0,
    denial_counts JSONB DEFAULT '{}',
    last_triggered_at TIMESTAMPTZ,
    last_reset_at TIMESTAMPTZ,
    reset_by VARCHAR(255)
);

INSERT INTO kill_switch_state (id, armed, active) VALUES (1, TRUE, FALSE)
ON CONFLICT (id) DO NOTHING;

-- ===== CIRCUIT-BREAKER STATE (per-agent) =====
CREATE TABLE IF NOT EXISTS circuit_breaker_state (
    agent_id VARCHAR(64) PRIMARY KEY,
    failures JSONB DEFAULT '[]',
    state VARCHAR(20) NOT NULL DEFAULT 'CLOSED' CHECK (state IN ('CLOSED', 'OPEN', 'HALF_OPEN')),
    tripped_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_breaker_state ON circuit_breaker_state(state);

-- ===== USERS (Dashboard) =====
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) CHECK (role IN ('admin', 'operator', 'viewer')) DEFAULT 'viewer',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ===== TRIGGER: Auto-update search vector =====
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
