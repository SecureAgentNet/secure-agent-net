import Link from 'next/link';
import { Github, Twitter } from 'lucide-react';

const footerLinks = {
  Product: ['/features', '/architecture', '/pricing', '/install'],
  Developers: ['/docs', '/api', 'https://github.com/SecureAgentNet/secure-agent-net', '/community'],
  Company: ['/about', '/community', '/blog', 'mailto:secureagentnet@example.com'],
  Legal: ['https://github.com/SecureAgentNet/secure-agent-net/blob/main/LICENSE', 'https://github.com/SecureAgentNet/secure-agent-net/blob/main/SECURITY.md'],
};

export default function Footer() {
  return (
    <footer className="bg-gray-50 dark:bg-dark-surface border-t border-gray-200 dark:border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
          {Object.entries(footerLinks).map(([title, links]) => (
            <div key={title}>
              <h3 className="font-semibold text-sm text-gray-900 dark:text-white mb-3">{title}</h3>
              <ul className="space-y-2">
                {links.map((l, i) => (
                  <li key={i}>
                    {l.startsWith('http') || l.startsWith('mailto') ? (
                      <a href={l} className="text-sm text-gray-500 dark:text-gray-400 hover:text-brand-blue dark:hover:text-brand-blue transition-colors">{l.split('/').pop()?.replace('-',' ')}</a>
                    ) : (
                      <Link href={l} className="text-sm text-gray-500 dark:text-gray-400 hover:text-brand-blue dark:hover:text-brand-blue transition-colors">{l.replace('/','')}</Link>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="mt-8 pt-8 border-t border-gray-200 dark:border-gray-700 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-sm text-gray-400">2026 SecureAgentNet. MIT License. Built with Next.js + Tailwind.</p>
          <div className="flex gap-4">
            <a href="https://github.com/SecureAgentNet/secure-agent-net" className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"><Github className="w-5 h-5" /></a>
            <a href="https://twitter.com" className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"><Twitter className="w-5 h-5" /></a>
          </div>
        </div>
      </div>
    </footer>
  );
}
