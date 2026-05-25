import { Shield, FileText, Container, Brain, Key, Zap, Terminal, Globe, Database, Network } from 'lucide-react';

const features = [
  [Shield, 'Challenge-Response Auth', 'Ed25519 signatures. No passwords stored. Zero-knowledge by design.'],
  [FileText, 'Tamper-Proof Audit Trail', 'HMAC-signed via Vault Transit. Verify integrity with forensics verify.'],
  [Container, 'OS-Level Isolation', 'Docker sandbox + seccomp + AppArmor + read-only rootfs. No escape.'],
  [Brain, 'LLM Semantic Evaluation', 'Ollama analyzes intent. Microsoft Presidio redacts PII before LLM sees data.'],
  [Key, 'Intent Scoping', 'IntentCapsule restricts agents to approved actions. Goal-hijack detection.'],
  [Zap, 'Real-Time Threat Detection', 'RogueDetector anomaly scoring. KillSwitch halts all operations.'],
  [Terminal, 'CLI-First Design', '14 subcommands. Rich terminal output. Two entry points: secureagentnet & san.'],
  [Globe, 'Cross-Platform', 'Linux, macOS, Windows. Docker Desktop detection. Zero-dependency minimal mode.'],
  [Database, 'Database Backed', '12 ORM models. SQLite dev, PostgreSQL prod. JSON fallback.'],
  [Network, 'MCP Protocol Gateway', '8 FastAPI endpoints, JWT middleware, tool discovery, heartbeat.'],
];

export default function FeaturesPage() {
  return (
    <>
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h1 className="text-4xl font-extrabold">Enterprise-Grade Security</h1>
          <p className="mt-4 text-lg text-gray-600">Everything you need to secure, monitor, and audit autonomous AI systems.</p>
        </div>
      </section>
      <section className="py-16 bg-white">
        <div className="max-w-5xl mx-auto px-4 grid sm:grid-cols-2 gap-5">
          {features.map(([Icon, title, desc]) => (
            <div key={title} className="flex gap-4 p-5 rounded-xl border border-gray-200 bg-slate-50">
              <Icon className="w-7 h-7 text-blue-600 shrink-0 mt-0.5" />
              <div><h3 className="font-bold">{title}</h3><p className="text-sm text-gray-600 mt-1">{desc}</p></div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
