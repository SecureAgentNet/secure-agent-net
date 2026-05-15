-- SecureAgentNet PostgreSQL Schema

-- Enums
CREATE TYPE agent_status AS ENUM ('active', 'suspended', 'rogue');
CREATE TYPE policy_action AS ENUM ('allow', 'deny', 'requires_approval');

-- Agents Table: Stores identity and cryptographic verification keys for AI Agents
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    public_key TEXT UNIQUE NOT NULL,
    status agent_status DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Agent Capabilities: Whitelists specific tools/actions an agent is allowed to use
CREATE TABLE agent_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    capability_name VARCHAR(100) NOT NULL,
    is_allowed BOOLEAN DEFAULT true,
    UNIQUE(agent_id, capability_name)
);

-- Policies Table: Stores rules for the Semantic Evaluator (Decide Phase)
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    action_type policy_action NOT NULL,
    conditions JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit Logs Table: Stores immutable records of agent actions and LLM risk scores
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    action_requested VARCHAR(255) NOT NULL,
    resource_target VARCHAR(255),
    intent_summary TEXT,
    llm_risk_score DECIMAL(3, 2), -- 0.00 to 1.00 (1.00 being critical risk)
    decision VARCHAR(50) NOT NULL, -- 'allowed', 'blocked', 'failed'
    execution_time_ms INTEGER
);

-- Indexes for performance
CREATE INDEX idx_audit_logs_agent_id ON audit_logs(agent_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
