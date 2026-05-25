const phases = [
  { step: 1, name: 'IDENTIFY', color: 'text-blue-600', bg: 'bg-blue-50', border: 'border-blue-200', items: ['Challenge-response auth (Ed25519/RSA)', 'IdentityRegistry, CapabilityProfiler', 'RogueDetector anomaly scoring', 'CircuitBreaker per-agent tracking', 'KillSwitch system-wide halt'] },
  { step: 2, name: 'TRACK', color: 'text-green-600', bg: 'bg-green-50', border: 'border-green-200', items: ['ReasoningCaptureMiddleware wraps execution', 'Vault Transit HMAC-signed audit logs', 'AgentAuditor → VaultAuditClient', 'LogIndexer, ForensicQueryEngine', 'forensics verify for tamper detection'] },
  { step: 3, name: 'DECIDE', color: 'text-amber-600', bg: 'bg-amber-50', border: 'border-amber-200', items: ['Tier 1: RuleFilter (DB-backed policies)', 'Tier 2: PiiRedactor (Presidio, 6 recognizers)', 'Tier 3: SemanticEvaluator (Ollama LLM)', 'DecisionLog persisted to database'] },
  { step: 4, name: 'CONTAIN', color: 'text-red-600', bg: 'bg-red-50', border: 'border-red-200', items: ['Docker sandbox with configurable timeout', 'seccomp: 76 allowed syscalls', 'AppArmor: deny /proc/sys, /boot, /root', 'Network isolation, OOM detection, metrics'] },
];
const modes = [
  ['docker', 'Docker, Redis, Ollama, Vault', 'Full security — production'],
  ['local', 'SQLite only', 'Development — no external services'],
  ['minimal', 'JSON files only', 'Zero dependencies — instant'],
];

export default function ArchitecturePage() {
  return (
    <>
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h1 className="text-4xl font-extrabold">Architecture</h1>
          <p className="mt-4 text-lg text-gray-600">The ITCD pipeline design, component interactions, and deployment modes.</p>
        </div>
      </section>
      <section className="py-16 bg-white">
        <div className="max-w-5xl mx-auto px-4">
          <div className="flex justify-center gap-2 mb-12 text-3xl font-extrabold text-gray-300">
            {phases.map((p, i) => (<span key={i}><span className={p.color}>{p.step}</span>{i < 3 && '  →  '}</span>))}
          </div>
          <div className="grid md:grid-cols-2 gap-5">
            {phases.map(p => (
              <div key={p.name} className={`p-6 rounded-xl border ${p.border} ${p.bg}`}>
                <h3 className={`font-extrabold text-lg ${p.color}`}>{p.name}</h3>
                <ul className="mt-3 space-y-1.5 text-sm text-gray-700">
                  {p.items.map((item, i) => <li key={i} className="flex gap-2"><span className="text-green-500">•</span>{item}</li>)}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>
      <section className="py-16 bg-slate-50 text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h2 className="text-2xl font-bold mb-6">Deployment Modes</h2>
          <div className="grid grid-cols-3 gap-4">
            {modes.map(([mode, deps, desc]) => (
              <div key={mode} className="p-4 rounded-xl border border-gray-200 bg-white">
                <div className="font-mono font-bold text-blue-600">{mode}</div>
                <div className="text-xs text-gray-500 mt-1">{deps}</div>
                <div className="text-sm mt-2">{desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
