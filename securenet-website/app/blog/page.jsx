import Link from 'next/link';

const posts = [
  ['prompt-injection-detection', 'security', 'May 10, 2026', '8 min', 'How We Achieved 97% Prompt Injection Detection', 'Dive into our 3-tier semantic evaluation — rules, PII redaction, and LLM analysis.'],
  ['container-escape-prevention', 'contain', 'May 2, 2026', '10 min', 'Container Escape Prevention: Seccomp Deep Dive', 'How seccomp, AppArmor, RO rootfs, and capability dropping achieve zero escapes.'],
  ['rogue-agent-detection', 'identify', 'Apr 22, 2026', '6 min', 'Building Rogue Agent Detection', 'Tracking request patterns, failure rates, and capability escalation.'],
  ['forensic-logging-vault', 'track', 'Apr 10, 2026', '7 min', 'Forensic Logging with Vault Transit', 'HMAC-signed audit logs are tamper-proof and verifiable with one CLI command.'],
];

export default function BlogPage() {
  return (
    <>
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h1 className="text-4xl font-extrabold">Blog</h1>
          <p className="mt-4 text-lg text-gray-600">Technical deep-dives, security research, and release notes.</p>
        </div>
      </section>
      <section className="py-16 bg-white">
        <div className="max-w-3xl mx-auto px-4 space-y-8">
          {posts.map(([slug, tag, date, read, title, excerpt]) => (
            <article key={slug} className="p-6 rounded-xl border border-gray-200 bg-slate-50">
              <div className="flex gap-3 text-xs text-gray-500 mb-2">
                <span className="px-2 py-0.5 rounded bg-blue-100 text-blue-600 font-mono">{tag}</span>
                <span>{date}</span>
                <span>{read}</span>
              </div>
              <Link href={`/blog/${slug}`} className="text-xl font-bold hover:text-blue-600">{title}</Link>
              <p className="text-sm text-gray-600 mt-2">{excerpt}</p>
              <Link href={`/blog/${slug}`} className="inline-block mt-3 text-sm font-semibold text-blue-600 hover:underline">Read more →</Link>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}
