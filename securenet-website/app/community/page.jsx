'use client';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { MessageCircle, Github, Youtube, Calendar } from 'lucide-react';

const channels = [
  { icon: Github, title: 'GitHub', desc: 'Star the repo, report bugs, request features, submit PRs. 397 tests and counting.', cta: 'View on GitHub', href: 'https://github.com/SecureAgentNet/secure-agent-net' },
  { icon: MessageCircle, title: 'Community', desc: 'Join discussions, get help, and share your SecureAgentNet setups with other developers.', cta: 'Join the Conversation', href: 'https://github.com/SecureAgentNet/secure-agent-net/discussions' },
  { icon: Youtube, title: 'YouTube', desc: 'Installation tutorials, architecture deep-dives, red team demos, and monthly office hours.', cta: 'Subscribe', href: '#' },
  { icon: Calendar, title: 'Events', desc: 'Monthly community calls (Zoom), annual virtual conference, and Capture-the-Flag competitions.', cta: 'View Calendar', href: '#' },
];

export default function CommunityPage() {
  return (
    <>
      <section className="section bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="container text-center max-w-3xl">
          <motion.h1 className="heading" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>Join the Community</motion.h1>
          <motion.p className="subheading mx-auto" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>Help shape the future of AI agent security.</motion.p>
        </div>
      </section>
      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container max-w-5xl">
          <div className="grid sm:grid-cols-2 gap-6">
            {channels.map((c, i) => (
              <motion.div key={i} className="p-6 rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-dark-surface" initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}>
                <c.icon className="w-8 h-8 text-brand-blue mb-3" />
                <h3 className="font-bold text-lg mb-1">{c.title}</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">{c.desc}</p>
                <a href={c.href} className="text-sm font-semibold text-brand-blue hover:underline">{c.cta} →</a>
              </motion.div>
            ))}
          </div>
          <div className="mt-12 text-center">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Want to contribute? Check out the <Link href="https://github.com/SecureAgentNet/secure-agent-net/blob/main/CONTRIBUTING.md" className="text-brand-blue hover:underline">Contribution Guide</Link>.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
