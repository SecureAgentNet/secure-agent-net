'use client';
import { motion } from 'framer-motion';
import Link from 'next/link';

const phases = [
  { step: 1, name: 'IDENTIFY', color: 'text-blue-500', bg: 'bg-blue-50 dark:bg-blue-950', border: 'border-blue-200 dark:border-blue-800', items: ['Challenge-response auth (Ed25519/RSA)', 'IdentityRegistry + CapabilityProfiler', 'RogueDetector anomaly scoring', 'CircuitBreaker per-agent tracking', 'KillSwitch system-wide halt', 'IntentCapsule goal validation'] },
  { step: 2, name: 'TRACK', color: 'text-green-500', bg: 'bg-green-50 dark:bg-green-950', border: 'border-green-200 dark:border-green-800', items: ['ReasoningCaptureMiddleware wraps execution', 'Vault Transit HMAC-signed audit logs', 'AgentAuditor → VaultAuditClient', 'LogIndexer with phase/severity queries', 'forensics verify for tamper detection'] },
  { step: 3, name: 'DECIDE', color: 'text-yellow-500', bg: 'bg-yellow-50 dark:bg-yellow-950', border: 'border-yellow-200 dark:border-yellow-800', items: ['Tier 1: RuleFilter (DB-backed policies)', 'Tier 2: PiiRedactor (Presidio, 6 recognizers)', 'Tier 3: SemanticEvaluator (Ollama LLM)', 'DecisionLog persisted to database', 'Fail-closed on any tier failure'] },
  { step: 4, name: 'CONTAIN', color: 'text-red-500', bg: 'bg-red-50 dark:bg-red-950', border: 'border-red-200 dark:border-red-800', items: ['Docker sandbox with 30s timeout', 'seccomp: 76 allowed syscalls', 'AppArmor: deny /proc/sys, /boot, /root', 'Read-only rootfs + tmpfs scratch', 'Network isolation (none/strict/moderate)', 'OOM detection + resource metrics'] },
];

const stack = [
  { layer: 'Web UI', tech: 'Flask + FastAPI', desc: 'Dashboard on /dashboard, REST API on /api/v1' },
  { layer: 'Pipeline', tech: 'ITCD Pipeline (Python)', desc: 'Async execution with ReasoningCaptureMiddleware' },
  { layer: 'Security', tech: 'Vault + Presidio + Ollama', desc: 'Audit signing, PII redaction, semantic eval' },
  { layer: 'Sandbox', tech: 'Docker + seccomp + AppArmor', desc: 'Ephemeral containers with OS-level isolation' },
  { layer: 'Data', tech: 'PostgreSQL + Redis + SQLite', desc: 'Configurable backend per deploy mode' },
  { layer: 'Infra', tech: 'Linux / macOS / Windows', desc: 'Docker Desktop for non-Linux hosts' },
];

export default function ArchitecturePage() {
  return (
    <>
      <section className="section bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="container text-center max-w-3xl">
          <motion.h1 className="heading" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>Architecture</motion.h1>
          <motion.p className="subheading mx-auto" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>The ITCD pipeline design, data flow, and component interactions.</motion.p>
        </div>
      </section>

      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container max-w-5xl">
          <div className="flex flex-col md:flex-row items-center justify-center gap-2 mb-16">
            {phases.map((p, i) => (
              <div key={i} className="flex items-center">
                <div className={`w-16 h-16 rounded-2xl ${p.bg} border ${p.border} flex items-center justify-center text-2xl font-extrabold ${p.color}`}>{p.step}</div>
                {i < 3 && <div className="text-3xl text-gray-300 dark:text-gray-600 mx-1 md:mx-3">→</div>}
              </div>
            ))}
          </div>
          <div className="grid md:grid-cols-2 gap-6">
            {phases.map((p, i) => (
              <motion.div key={i} className={`p-6 rounded-xl ${p.bg} border ${p.border}`} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}>
                <h3 className={`font-extrabold text-lg ${p.color} mb-3`}>{p.name}</h3>
                <ul className="space-y-1.5">
                  {p.items.map((item, j) => (
                    <li key={j} className="text-sm text-gray-700 dark:text-gray-300 flex items-start gap-2">
                      <span className="text-brand-green mt-0.5">•</span> {item}
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-16 bg-gray-50 dark:bg-dark-surface">
        <div className="container max-w-4xl">
          <h2 className="heading text-center mb-10">Technology Stack</h2>
          <div className="space-y-3">
            {stack.map((s, i) => (
              <div key={i} className="flex flex-col sm:flex-row sm:items-center gap-3 p-4 rounded-xl bg-white dark:bg-dark-bg border border-gray-200 dark:border-gray-800">
                <span className="text-xs font-mono font-bold text-brand-blue bg-blue-50 dark:bg-blue-950 px-3 py-1 rounded w-fit">{s.layer}</span>
                <span className="font-semibold text-sm">{s.tech}</span>
                <span className="text-sm text-gray-500 dark:text-gray-400 sm:ml-auto">{s.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container text-center max-w-2xl">
          <h2 className="heading mb-4">Deployment Modes</h2>
          <div className="grid grid-cols-3 gap-4 mt-8">
            {[
              { mode: 'docker', deps: 'Docker, Redis, Ollama, Vault', desc: 'Full security — production' },
              { mode: 'local', deps: 'SQLite only', desc: 'Development — no external services' },
              { mode: 'minimal', deps: 'JSON files only', desc: 'Zero dependencies — instant' },
            ].map(m => (
              <div key={m.mode} className="p-4 rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-dark-surface">
                <div className="font-mono font-bold text-brand-blue mb-1">{m.mode}</div>
                <div className="text-xs text-gray-500 mb-2">{m.deps}</div>
                <div className="text-sm">{m.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-16 bg-gradient-to-r from-brand-blue to-brand-purple text-center">
        <div className="container">
          <h2 className="text-3xl font-extrabold text-white mb-4">Ready to dive deeper?</h2>
          <div className="flex gap-4 justify-center">
            <Link href="/docs" className="px-6 py-3 bg-white text-brand-blue font-bold rounded-lg">Read the Docs</Link>
            <a href="https://github.com/SecureAgentNet/secure-agent-net/blob/main/docs/architecture/Phase2_Track.md" className="px-6 py-3 border border-white/30 text-white font-bold rounded-lg">Phase 2 Architecture</a>
          </div>
        </div>
      </section>
    </>
  );
}
