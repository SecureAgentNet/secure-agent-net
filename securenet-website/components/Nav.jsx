'use client';
import { useState } from 'react';
import Link from 'next/link';
import { Bars3Icon, XMarkIcon } from '@heroicons/react/24/outline';
import { Shield } from 'lucide-react';

const links = [
  { href: '/install', label: 'Install' },
  { href: '/docs', label: 'Docs' },
  { href: '/features', label: 'Features' },
  { href: '/architecture', label: 'Architecture' },
  { href: '/pricing', label: 'Pricing' },
  { href: '/blog', label: 'Blog' },
];

export default function Nav() {
  const [open, setOpen] = useState(false);
  return (
    <nav className="sticky top-0 z-50 bg-white/80 dark:bg-dark-bg/80 backdrop-blur-md border-b border-gray-200 dark:border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link href="/" className="flex items-center gap-2 font-bold text-xl text-gray-900 dark:text-white">
            <Shield className="w-6 h-6 text-brand-blue" />
            SecureAgentNet
          </Link>
          <div className="hidden md:flex items-center gap-1">
            {links.map(l => (
              <Link key={l.href} href={l.href} className="px-3 py-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand-blue dark:hover:text-brand-blue rounded-lg hover:bg-gray-100 dark:hover:bg-dark-surface transition-colors">
                {l.label}
              </Link>
            ))}
            <Link href="https://github.com/SecureAgentNet/secure-agent-net" className="ml-2 px-4 py-2 text-sm font-medium text-white bg-brand-blue hover:bg-blue-700 rounded-lg transition-colors">
              GitHub
            </Link>
          </div>
          <button onClick={() => setOpen(!open)} className="md:hidden p-2 text-gray-600 dark:text-gray-300">
            {open ? <XMarkIcon className="w-6 h-6" /> : <Bars3Icon className="w-6 h-6" />}
          </button>
        </div>
        {open && (
          <div className="md:hidden pb-4 space-y-1">
            {links.map(l => (
              <Link key={l.href} href={l.href} onClick={() => setOpen(false)} className="block px-3 py-2 text-gray-600 dark:text-gray-300 hover:text-brand-blue rounded-lg">
                {l.label}
              </Link>
            ))}
            <Link href="https://github.com/SecureAgentNet/secure-agent-net" className="block px-4 py-2 text-sm font-medium text-white bg-brand-blue rounded-lg text-center">
              GitHub
            </Link>
          </div>
        )}
      </div>
    </nav>
  );
}
