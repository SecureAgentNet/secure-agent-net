'use client';
import { useState } from 'react';
import Link from 'next/link';
import { Shield, Menu, X, Github } from 'lucide-react';

const links = [
  ['/docs', 'Docs'],
  ['/features', 'Features'],
  ['/architecture', 'Architecture'],
  ['/hitl', 'HITL'],
  ['/behavior', 'Behavior'],
  ['/blog', 'Blog'],
];

export default function Nav() {
  const [open, setOpen] = useState(false);
  return (
    <nav className="sticky top-0 z-50 bg-slate-900/80 backdrop-blur-lg border-b border-white/10">
      <div className="max-w-6xl mx-auto px-4 flex items-center justify-between h-16">
        <Link href="/" className="flex items-center gap-2 font-bold text-xl">
          <Shield className="w-7 h-7 text-cyan-400" />
          <span className="text-white">Secure<span className="text-cyan-400">AgentNet</span></span>
        </Link>
        <div className="hidden md:flex items-center gap-1">
          {links.map(([href, label]) => (
            <Link key={href} href={href} className="px-3 py-2 text-sm text-slate-300 hover:text-white rounded-lg hover:bg-white/5 transition-colors">{label}</Link>
          ))}
          <a href="https://github.com/SecureAgentNet/secure-agent-net" target="_blank" rel="noopener noreferrer" className="ml-2 flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors">
            <Github size={16} />
            GitHub
          </a>
        </div>
        <button onClick={() => setOpen(!open)} className="md:hidden p-2 text-slate-300 hover:text-white">
          {open ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>
      {open && (
        <div className="md:hidden px-4 pb-4 space-y-1 bg-slate-900/95 border-b border-white/10">
          {links.map(([href, label]) => (
            <Link key={href} href={href} onClick={() => setOpen(false)} className="block px-3 py-2 text-slate-300 hover:text-white rounded-lg hover:bg-white/5">{label}</Link>
          ))}
          <a href="https://github.com/SecureAgentNet/secure-agent-net" target="_blank" rel="noopener noreferrer" className="block px-4 py-2 text-center text-white bg-cyan-600 rounded-lg">GitHub</a>
        </div>
      )}
    </nav>
  );
}
