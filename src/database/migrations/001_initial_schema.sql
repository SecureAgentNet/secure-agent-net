-- Migration 001: Initial Schema
-- Applied against PostgreSQL 14+

BEGIN;

CREATE TYPE agent_status AS ENUM ('pending', 'active', 'suspended', 'revoked', 'rogue');
CREATE TYPE policy_action AS ENUM ('allow', 'deny', 'requires_approval');
CREATE TYPE event_severity AS ENUM ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL');
CREATE TYPE pipeline_phase AS ENUM ('IDENTIFY', 'TRACK', 'CONTAIN', 'DECIDE');
CREATE TYPE final_decision AS ENUM ('APPROVE', 'DENY', 'ESCALATE');

CREATE TABLE agents (
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

CREATE TABLE agent_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(agent_id) ON DELETE CASCADE,
    capability_name VARCHAR(100) NOT NULL,
    capability_level INT DEFAULT 0 CHECK (capability_level >= 0 AND capability_level <= 4),
    is_allowed BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(agent_id, capability_name)
);

CREATE TABLE auth_events (
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

CREATE TABLE containers (
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

CREATE TABLE decision_log (
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

CREATE TABLE intent_capsules (
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

CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) CHECK (role IN ('admin', 'operator', 'viewer')) DEFAULT 'viewer',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    active BOOLEAN DEFAULT TRUE
);

COMMIT;
