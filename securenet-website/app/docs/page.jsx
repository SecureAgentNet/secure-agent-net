import Link from 'next/link';
import { Book, Terminal, Shield, Wrench } from 'lucide-react';

const docCategories = [
  { icon: Book, title: 'Getting Started', links: ['Introduction', 'Quick Start', 'Installation', 'First Agent'] },
  { icon: Shield, title: 'Core Concepts', links: ['ITCD Pipeline Overview', 'Phase 1: Identify', 'Phase 2: Track', 'Phase 3: Decide', 'Phase 4: Contain'] },
  { icon: Terminal, title: 'API Reference', links: ['REST API', 'CLI Commands', 'MCP Gateway', 'Web Dashboard'] },
  { icon: Wrench, title: 'Guides', links: ['Configuration', 'Security Hardening', 'Monitoring & Alerts', 'Backup & Recovery'] },
];

export default function DocsPage() {
  return (
    <>
      <section className="section bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="container text-center max-w-3xl">
          <h1 className="heading">Documentation</h1>
          <p className="subheading mx-auto">Everything you need to deploy, configure, and extend SecureAgentNet.</p>
        </div>
      </section>
      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container max-w-5xl">
          <div className="grid sm:grid-cols-2 gap-6">
            {docCategories.map((c, i) => (
              <div key={i} className="p-6 rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-dark-surface">
                <c.icon className="w-6 h-6 text-brand-blue mb-3" />
                <h3 className="font-bold text-lg mb-3">{c.title}</h3>
                <ul className="space-y-2">
                  {c.links.map((l, j) => (
                    <li key={j}>
                      <Link href={`/docs/${l.toLowerCase().replace(/\s+/g, '-').replace(':', '')}`} className="text-sm text-gray-600 dark:text-gray-400 hover:text-brand-blue transition-colors">{l}</Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <div className="mt-12 p-6 rounded-xl bg-gray-50 dark:bg-dark-surface border border-gray-200 dark:border-gray-800">
            <h3 className="font-bold mb-3">Quick Links</h3>
            <div className="grid sm:grid-cols-2 gap-2">
              <Link href="https://github.com/SecureAgentNet/secure-agent-net/blob/main/docs/architecture/Phase2_Track.md" className="text-sm text-brand-blue hover:underline">Phase 2: Track Architecture</Link>
              <Link href="/docs/cli" className="text-sm text-brand-blue hover:underline">CLI Command Reference</Link>
              <Link href="/docs/api" className="text-sm text-brand-blue hover:underline">MCP API Reference</Link>
              <Link href="https://github.com/SecureAgentNet/secure-agent-net/blob/main/SECURITY.md" className="text-sm text-brand-blue hover:underline">Security Policy</Link>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
