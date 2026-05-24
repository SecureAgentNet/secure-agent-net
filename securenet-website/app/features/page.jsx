'use client';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { Shield, FileSearch, Container, Brain, Key, Zap, Terminal, Globe, Database, Network } from 'lucide-react';

const features = [
  { icon: Shield, title: 'Challenge-Response Auth', desc: 'Ed25519 cryptographic authentication. Agents prove identity by signing a nonce — no passwords stored. Zero-knowledge by design.' },
  { icon: FileSearch, title: 'Tamper-Proof Audit Trail', desc: 'Every agent intent is HMAC-signed via HashiCorp Vault Transit. Verify log integrity with `forensics verify` CLI command.' },
  { icon: Container, title: 'OS-Level Isolation', desc: 'Docker sandbox with seccomp whitelisting, read-only root filesystem, dropped capabilities, and network isolation.' },
  { icon: Brain, title: 'LLM Semantic Evaluation', desc: 'Local Ollama models analyze intent for prompt injection, goal hijacking, and data exfiltration. Microsoft Presidio redacts PII before LLM sees data.' },
  { icon: Key, title: 'Intent Scoping', desc: 'IntentCapsule restricts agents to approved actions within a session. Goal-hijack detection blocks deviation from the original task.' },
  { icon: Zap, title: 'Real-Time Threat Detection', desc: 'RogueDetector scores agents on request pattern anomalies. KillSwitch halts all operations at the first sign of an attack.' },
  { icon: Terminal, title: 'CLI-First Design', desc: '14 subcommands for full control. Two entry points: `secureagentnet` and `san`. Rich terminal output with tables, colors, and panels.' },
  { icon: Globe, title: 'Cross-Platform', desc: 'Runs on Linux, macOS, and Windows. Docker Desktop detection. Seccomp and AppArmor gracefully skipped on non-Linux hosts.' },
  { icon: Database, title: 'Database Backed', desc: '12 SQLAlchemy ORM models. SQLite for dev, PostgreSQL for production. JSON file fallback if database is unavailable.' },
  { icon: Network, title: 'MCP Protocol Gateway', desc: '8 FastAPI endpoints with JWT middleware. Tool discovery, agent heartbeat, challenge-response auth, token refresh.' },
];

export default function FeaturesPage() {
  return (
    <>
      <section className="section bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="container text-center max-w-3xl">
          <motion.h1 className="heading" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>Enterprise-Grade Security for AI Agents</motion.h1>
          <motion.p className="subheading mx-auto" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>Everything you need to secure, monitor, and audit autonomous AI systems.</motion.p>
        </div>
      </section>
      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container max-w-5xl">
          <div className="grid sm:grid-cols-2 gap-6">
            {features.map((f, i) => (
              <motion.div key={i} className="flex gap-4 p-6 rounded-xl border border-gray-200 dark:border-gray-800 hover:shadow-lg transition-all bg-gray-50 dark:bg-dark-surface" initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.05 }}>
                <f.icon className="w-8 h-8 text-brand-blue shrink-0" />
                <div>
                  <h3 className="font-bold text-lg mb-1">{f.title}</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">{f.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
