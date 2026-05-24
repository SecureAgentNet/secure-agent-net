'use client';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { Check } from 'lucide-react';

const tiers = [
  {
    name: 'Open Source', price: 'Free', period: 'forever', color: 'border-gray-200', highlight: false,
    features: ['Full ITCD pipeline', 'Unlimited agents', 'Community support', 'Self-hosted deployment', 'All features included', 'MIT License'],
    cta: { text: 'Get Started', href: '/install' },
  },
  {
    name: 'Managed Cloud', price: '$99', period: '/month', color: 'border-brand-blue ring-2 ring-brand-blue', highlight: true, badge: 'Coming Q4 2026',
    features: ['Everything in Open Source', 'Managed infrastructure', 'Automatic updates', '99.9% uptime SLA', 'Email support (24h response)', 'SOC 2 + ISO 27001'],
    cta: { text: 'Join Waitlist', href: '#' },
  },
  {
    name: 'Enterprise', price: 'Custom', period: '', color: 'border-gray-200', highlight: false,
    features: ['Everything in Managed Cloud', 'On-premise deployment', 'Dedicated Slack channel', 'Custom SLA (up to 99.99%)', 'Advanced threat intelligence', 'Quarterly security audits', 'White-glove onboarding'],
    cta: { text: 'Contact Sales', href: 'mailto:secureagentnet@example.com' },
  },
];

export default function PricingPage() {
  return (
    <>
      <section className="section bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="container text-center max-w-3xl">
          <motion.h1 className="heading" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>Free Forever, Open Source Always</motion.h1>
          <motion.p className="subheading mx-auto" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>The core ITCD pipeline is MIT licensed and will always be free. Managed Cloud helps fund continued development.</motion.p>
        </div>
      </section>
      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container max-w-5xl">
          <div className="grid md:grid-cols-3 gap-6">
            {tiers.map((t, i) => (
              <motion.div key={i} className={`relative p-8 rounded-2xl border ${t.color} bg-white dark:bg-dark-surface flex flex-col`} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}>
                {t.badge && <span className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-brand-blue text-white text-xs font-bold rounded-full">{t.badge}</span>}
                <h3 className="text-xl font-bold">{t.name}</h3>
                <div className="mt-3 mb-6">
                  <span className="text-4xl font-extrabold">{t.price}</span>
                  <span className="text-gray-500 dark:text-gray-400 text-sm">{t.period}</span>
                </div>
                <ul className="space-y-3 flex-1">
                  {t.features.map((f, j) => (
                    <li key={j} className="flex items-start gap-2 text-sm">
                      <Check className="w-4 h-4 text-brand-green shrink-0 mt-0.5" />
                      <span className="text-gray-600 dark:text-gray-400">{f}</span>
                    </li>
                  ))}
                </ul>
                <Link href={t.cta.href} className={`mt-8 block text-center py-3 rounded-lg font-semibold transition-all ${t.highlight ? 'bg-brand-blue text-white hover:bg-blue-700' : 'border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:border-brand-blue'}`}>{t.cta.text}</Link>
              </motion.div>
            ))}
          </div>
          <div className="text-center mt-12">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              <strong>Q: Is it really free forever?</strong> Yes — the open-source core is MIT licensed. Managed Cloud will fund development. <Link href="/docs" className="text-brand-blue hover:underline">Learn more</Link>
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
