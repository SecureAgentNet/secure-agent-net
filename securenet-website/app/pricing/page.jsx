import Link from 'next/link';
import { Check } from 'lucide-react';

const tiers = [
  { name: 'Open Source', price: 'Free', period: 'forever', features: ['Full ITCD pipeline','Unlimited agents','Community support','Self-hosted','MIT License'], cta: 'Get Started', href: '/install', highlight: false },
  { name: 'Managed Cloud', price: '$99', period: '/month', badge: 'Coming Q4 2026', features: ['Everything in Open Source','Managed infra','Auto updates','99.9% SLA','SOC 2 + ISO 27001'], cta: 'Join Waitlist', href: '#', highlight: true },
  { name: 'Enterprise', price: 'Custom', period: '', features: ['Everything in Managed','On-premise','Dedicated Slack','Custom SLA','Threat intel','White-glove onboarding'], cta: 'Contact Sales', href: 'mailto:secureagentnet@example.com', highlight: false },
];

export default function PricingPage() {
  return (
    <>
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h1 className="text-4xl font-extrabold">Free Forever, Open Source</h1>
          <p className="mt-4 text-lg text-gray-600">The core ITCD pipeline is MIT licensed and always will be.</p>
        </div>
      </section>
      <section className="py-16 bg-white">
        <div className="max-w-5xl mx-auto px-4 grid md:grid-cols-3 gap-6">
          {tiers.map(t => (
            <div key={t.name} className={`relative p-8 rounded-2xl border ${t.highlight ? 'border-blue-600 ring-2 ring-blue-600' : 'border-gray-200'} bg-white flex flex-col`}>
              {t.badge && <span className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-blue-600 text-white text-xs font-bold rounded-full">{t.badge}</span>}
              <h3 className="text-xl font-bold">{t.name}</h3>
              <div className="mt-3 mb-6"><span className="text-4xl font-extrabold">{t.price}</span><span className="text-gray-500 text-sm">{t.period}</span></div>
              <ul className="space-y-2 flex-1">{t.features.map(f => <li key={f} className="flex gap-2 text-sm text-gray-600"><Check size={16} className="text-green-500 shrink-0 mt-0.5" />{f}</li>)}</ul>
              <Link href={t.href} className={`mt-8 block text-center py-3 rounded-lg font-semibold ${t.highlight ? 'bg-blue-600 text-white hover:bg-blue-700' : 'border border-gray-300 text-gray-700 hover:border-blue-600'}`}>{t.cta}</Link>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
