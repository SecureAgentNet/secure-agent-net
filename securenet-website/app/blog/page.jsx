'use client';
import { motion } from 'framer-motion';
import Link from 'next/link';

const posts = [
  {
    title: 'How We Achieved 97% Prompt Injection Detection with a 7B LLM',
    date: 'May 10, 2026', read: '8 min', tag: 'security',
    excerpt: 'Dive deep into SecureAgentNet\'s 3-tier semantic evaluation — rule-based filtering, PII redaction, and local LLM analysis — and how it achieves high detection rates while maintaining low false positives.',
    slug: 'prompt-injection-detection',
  },
  {
    title: 'Container Escape Prevention: Seccomp and AppArmor Deep Dive',
    date: 'May 2, 2026', read: '10 min', tag: 'contain',
    excerpt: 'How we use 76 allowed syscalls with seccomp, AppArmor profiles, read-only root filesystems, and capability dropping to achieve zero container escapes in red team testing.',
    slug: 'container-escape-prevention',
  },
  {
    title: 'Building Rogue Agent Detection with Anomaly Scoring',
    date: 'Apr 22, 2026', read: '6 min', tag: 'identify',
    excerpt: 'How RogueDetector tracks request patterns, failure rates, and capability escalation attempts to identify compromised agents before they cause damage.',
    slug: 'rogue-agent-detection',
  },
  {
    title: 'Forensic Logging with HashiCorp Vault Transit',
    date: 'Apr 10, 2026', read: '7 min', tag: 'track',
    excerpt: 'How we moved from KV v2 to Vault Transit for HMAC-signed audit logs — ensuring tamper-proof forensic trails that can be verified with a single CLI command.',
    slug: 'forensic-logging-vault-transit',
  },
];

export default function BlogPage() {
  return (
    <>
      <section className="section bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="container text-center max-w-3xl">
          <motion.h1 className="heading" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>Blog</motion.h1>
          <motion.p className="subheading mx-auto" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>Technical deep-dives, security research, and release notes from the SecureAgentNet team.</motion.p>
        </div>
      </section>
      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container max-w-4xl">
          <div className="space-y-8">
            {posts.map((p, i) => (
              <motion.article key={i} className="p-6 rounded-xl border border-gray-200 dark:border-gray-800 hover:border-brand-blue/50 transition-all bg-gray-50 dark:bg-dark-surface" initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}>
                <div className="flex items-center gap-3 text-xs text-gray-500 mb-2">
                  <span className="px-2 py-0.5 rounded bg-brand-blue/10 text-brand-blue font-mono">{p.tag}</span>
                  <span>{p.date}</span>
                  <span>{p.read}</span>
                </div>
                <Link href={`/blog/${p.slug}`} className="text-xl font-bold hover:text-brand-blue transition-colors">{p.title}</Link>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">{p.excerpt}</p>
                <Link href={`/blog/${p.slug}`} className="inline-block mt-3 text-sm font-semibold text-brand-blue hover:underline">Read more →</Link>
              </motion.article>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
