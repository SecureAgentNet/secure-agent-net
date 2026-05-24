#!/usr/bin/env python3
"""Seed test data into SecureAgentNet."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import logging

from src.identify.identity_registry import IdentityRegistry
from src.identify.capability_profiler import CapabilityProfiler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecureAgentNet.SeedData")


def seed_data():
    IdentityRegistry.initialize()

    agents_data = [
        {
            "name": "research-agent",
            "type": "LangChain",
            "description": "Research assistant for paper analysis and summarization",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0\n-----END PUBLIC KEY-----",
            "capabilities": {"web_search": True, "document_read": True, "summary_generation": True},
            "metadata": {"department": "research", "version": "1.0"},
            "created_by": "admin",
        },
        {
            "name": "code-agent",
            "type": "AutoGen",
            "description": "Code generation and review assistant",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1\n-----END PUBLIC KEY-----",
            "capabilities": {"code_execution": True, "file_read": True, "file_write": True},
            "metadata": {"department": "engineering", "version": "2.0"},
            "created_by": "admin",
        },
        {
            "name": "security-scan-agent",
            "type": "CrewAI",
            "description": "Automated security vulnerability scanner",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2\n-----END PUBLIC KEY-----",
            "capabilities": {"network_scan": True, "vulnerability_check": True, "report_generation": True},
            "metadata": {"department": "security", "version": "1.5"},
            "created_by": "admin",
        },
    ]

    for agent_data in agents_data:
        agent = IdentityRegistry.get_agent_by_name(agent_data["name"])
        if not agent:
            agent = IdentityRegistry.register_agent(agent_data)
            for capability in agent_data["capabilities"]:
                CapabilityProfiler.add_capability(agent["agent_id"], capability)
            logger.info(f"Seeded agent: {agent_data['name']} ({agent['agent_id']})")
        else:
            logger.info(f"Agent already exists: {agent_data['name']}")

    logger.info(f"Total agents: {IdentityRegistry.get_total_count()}")
    logger.info("Seed data complete.")


if __name__ == "__main__":
    seed_data()
