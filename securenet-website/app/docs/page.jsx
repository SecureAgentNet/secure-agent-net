import Link from 'next/link';

const sections = [
  ['Getting Started', ['Introduction', 'Quick Start', 'Installation']],
  ['Core Concepts', ['ITCD Pipeline', 'Phase 1: Identify', 'Phase 2: Track', 'Phase 3: Decide', 'Phase 4: Contain']],
  ['API Reference', ['CLI Commands', 'MCP Gateway', 'REST API']],
  ['Guides', ['Configuration', 'Security Hardening', 'Backup & Recovery']],
];

export default function DocsPage() {
  return (
    <>
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h1 className="text-4xl font-extrabold">Documentation</h1>
          <p className="mt-4 text-lg text-gray-600">Everything you need to deploy, configure, and extend SecureAgentNet.</p>
        </div>
      </section>
      <section className="py-16 bg-white">
        <div className="max-w-5xl mx-auto px-4 grid sm:grid-cols-2 gap-6">
          {sections.map(([title, links]) => (
            <div key={title} className="p-6 rounded-xl border border-gray-200 bg-slate-50">
              <h2 className="font-bold text-lg mb-3">{title}</h2>
              <ul className="space-y-2">
                {links.map(l => <li key={l}><Link href={`/docs/${l.toLowerCase().replace(/\s+/g, '-').replace(':', '')}`} className="text-sm text-gray-600 hover:text-blue-600">{l}</Link></li>)}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
