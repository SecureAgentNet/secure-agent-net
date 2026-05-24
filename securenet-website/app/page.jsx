'use client';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Shield, Key, FileSearch, Container, ArrowRight, Check, Terminal, Globe, Brain, Zap } from 'lucide-react';
import CodeBlock from '@/components/CodeBlock';

const fadeIn = { initial: { opacity: 0, y: 20 }, whileInView: { opacity: 1, y: 0 }, viewport: { once: true }, transition: { duration: 0.5 } };

const problems = [
  { icon: Terminal, title: 'Prompt Injection', desc: 'Attackers manipulate agent instructions through crafted inputs. Traditional firewalls cannot help.' },
  { icon: Zap, title: 'Excessive Agency', desc: 'Agents given unrestricted system access can exfiltrate data, execute arbitrary code, or worse.' },
  { icon: Globe, title: 'Zero Visibility', desc: 'Without forensic logging, you have no idea what your agents did or who compromised them.' },
];

const pipeline = [
  { name: 'IDENTIFY', color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30', desc: 'Cryptographic challenge-response auth. Verify identity, check capabilities, detect rogue behavior.' },
  { name: 'TRACK', color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/30', desc: 'HMAC-signed audit logs in Vault. Complete forensic trail — tamper-proof and verifiable.' },
  { name: 'DECIDE', color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', desc: '3-tier evaluation: rules → PII redaction → LLM analysis. Intent verified before execution.' },
  { name: 'CONTAIN', color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', desc: 'Docker sandbox + seccomp + AppArmor + read-only rootfs. No root access, no escape.' },
];

const features = [
  { icon: Shield, title: 'Challenge-Response Auth', desc: 'Agents prove identity with Ed25519 signatures. No passwords stored — zero-knowledge by design.' },
  { icon: FileSearch, title: 'Tamper-Proof Audit Trail', desc: 'Every intent HMAC-signed via Vault Transit. Verify integrity with `forensics verify`.' },
  { icon: Brain, title: 'LLM Semantic Evaluation', desc: 'Ollama models analyze intent for prompt injection and goal hijacking. PII redacted by Microsoft Presidio.' },
  { icon: Container, title: 'Docker Sandboxing', desc: 'Commands execute in ephemeral containers with seccomp, dropped capabilities, and network isolation.' },
  { icon: Key, title: 'Intent Scoping', desc: 'IntentCapsule restricts agents to approved actions. Goal-hijack detection blocks deviation.' },
  { icon: Globe, title: 'Cross-Platform', desc: 'Runs on Linux, macOS, and Windows. Docker Desktop detection. Zero-dependency minimal mode.' },
];

const stats = [
  { value: '397', label: 'Tests Passing' },
  { value: '8', label: 'MCP API Routes' },
  { value: '14', label: 'CLI Commands' },
  { value: '0', label: 'Container Escapes' },
];

export default function Home() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI2MCIgaGVpZ2h0PSI2MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTSA2MCAwIEwgMCAwIDAgNjAiIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2UyZThmMCIgc3Ryb2tlLXdpZHRoPSIxIi8+PC9wYXR0ZXJuPjwvZGVmcz48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSJ1cmwoI2dyaWQpIi8+PC9zdmc+')] opacity-40 dark:opacity-10" />
        <div className="container relative py-20 sm:py-32">
          <motion.div className="max-w-4xl mx-auto text-center" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7 }}>
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 text-sm font-medium mb-6">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              v2.0.0 — Production Ready
            </div>
            <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-gray-900 dark:text-white leading-tight">
              Secure Your AI Agents<br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-brand-blue via-brand-green to-brand-purple">Before They Secure Themselves</span>
            </h1>
            <p className="mt-6 text-lg sm:text-xl text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
              The first comprehensive zero-trust security orchestration framework for autonomous AI agents. Every action flows through a 4-phase ITCD pipeline.
            </p>
            <div className="mt-10 flex flex-wrap gap-4 justify-center">
              <Link href="/install" className="btn-primary text-lg">Get Started <ArrowRight className="w-5 h-5" /></Link>
              <a href="https://github.com/SecureAgentNet/secure-agent-net" className="btn-secondary text-lg">View on GitHub</a>
            </div>
            <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-6">
              {stats.map(s => (
                <div key={s.label} className="text-center">
                  <div className="text-3xl font-bold text-brand-blue">{s.value}</div>
                  <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">{s.label}</div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* Problem */}
      <section className="section bg-white dark:bg-dark-bg">
        <div className="container">
          <motion.div className="text-center max-w-3xl mx-auto mb-16" {...fadeIn}>
            <h2 className="heading">AI Agents Are Powerful. They&apos;re Also Vulnerable.</h2>
            <p className="subheading">The OWASP Top 10 for LLM Applications identifies critical risks that traditional security tools cannot address.</p>
          </motion.div>
          <div className="grid md:grid-cols-3 gap-8">
            {problems.map((p, i) => (
              <motion.div key={i} className="p-8 rounded-2xl border border-gray-200 dark:border-gray-800 hover:border-brand-blue/50 dark:hover:border-brand-blue/50 transition-all bg-white dark:bg-dark-surface" initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.15 }}>
                <p.icon className="w-8 h-8 text-brand-blue mb-4" />
                <h3 className="text-xl font-bold mb-2">{p.title}</h3>
                <p className="text-gray-600 dark:text-gray-400">{p.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Pipeline */}
      <section className="section bg-gray-50 dark:bg-dark-surface">
        <div className="container">
          <motion.div className="text-center max-w-3xl mx-auto mb-16" {...fadeIn}>
            <h2 className="heading">The ITCD Pipeline: Four Phases of Defense</h2>
            <p className="subheading">Every agent action passes through all four phases. If any phase fails, the action is blocked — never allowed.</p>
          </motion.div>
          <div className="grid md:grid-cols-4 gap-4">
            {pipeline.map((p, i) => (
              <motion.div key={i} className={`p-6 rounded-xl border ${p.border} ${p.bg} text-center`} initial={{ opacity: 0, x: -20 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}>
                <div className={`text-4xl font-extrabold ${p.color} mb-2`}>{i + 1}</div>
                <h3 className={`font-bold text-lg ${p.color}`}>{p.name}</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">{p.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Quick Start */}
      <section className="section bg-white dark:bg-dark-bg">
        <div className="container">
          <motion.div className="text-center max-w-3xl mx-auto mb-16" {...fadeIn}>
            <h2 className="heading">Install in One Command</h2>
            <p className="subheading">Works on Linux, macOS, and Windows. Choose your preferred method.</p>
          </motion.div>
          <div className="max-w-2xl mx-auto space-y-4">
            <CodeBlock code={`# macOS (Homebrew)\nbrew tap SecureAgentNet/tap\nbrew install secureagentnet`} />
            <CodeBlock code={`# Any OS (pip)\npip install secureagentnet\nsecureagentnet init --mode minimal\nsecureagentnet doctor`} language="bash" />
            <CodeBlock code={`# One-liner (curl)\ncurl -fsSL https://raw.githubusercontent.com/SecureAgentNet/secure-agent-net/main/scripts/install.sh | sh`} />
          </div>
          <div className="text-center mt-8">
            <Link href="/install" className="btn-primary">Full Installation Guide <ArrowRight className="w-4 h-4" /></Link>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="section bg-gray-50 dark:bg-dark-surface">
        <div className="container">
          <motion.div className="text-center max-w-3xl mx-auto mb-16" {...fadeIn}>
            <h2 className="heading">Everything You Need to Secure AI Agents</h2>
            <p className="subheading">Defense in depth across identity, audit, evaluation, and execution layers.</p>
          </motion.div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((f, i) => (
              <motion.div key={i} className="p-6 rounded-xl bg-white dark:bg-dark-bg border border-gray-200 dark:border-gray-800 hover:shadow-lg transition-shadow" initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.08 }}>
                <f.icon className="w-8 h-8 text-brand-blue mb-3" />
                <h3 className="font-bold text-lg mb-1">{f.title}</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Trust */}
      <section className="section bg-white dark:bg-dark-bg">
        <div className="container text-center">
          <motion.div {...fadeIn}>
            <h2 className="heading">Built with Industry Standards</h2>
            <div className="mt-10 flex flex-wrap justify-center gap-8 items-center opacity-60">
              {['Docker', 'PostgreSQL', 'HashiCorp Vault', 'Ollama', 'Microsoft Presidio', 'Redis', 'FastAPI', 'SQLAlchemy'].map(t => (
                <div key={t} className="px-4 py-2 rounded-lg bg-gray-100 dark:bg-dark-surface text-sm font-mono font-semibold text-gray-600 dark:text-gray-400">{t}</div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-16 bg-gradient-to-r from-brand-blue to-brand-purple">
        <div className="container text-center">
          <h2 className="text-3xl font-extrabold text-white mb-4">Ready to secure your AI agents?</h2>
          <p className="text-blue-100 mb-8 max-w-xl mx-auto">Install in under 5 minutes. Free and open source forever.</p>
          <div className="flex gap-4 justify-center">
            <Link href="/install" className="px-8 py-3 bg-white text-brand-blue font-bold rounded-lg hover:bg-gray-100 transition-all">Get Started</Link>
            <Link href="/docs" className="px-8 py-3 border border-white/30 text-white font-bold rounded-lg hover:bg-white/10 transition-all">Read the Docs</Link>
          </div>
        </div>
      </section>
    </>
  );
}
