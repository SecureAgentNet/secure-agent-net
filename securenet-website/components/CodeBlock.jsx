'use client';
import { useState } from 'react';

export default function CodeBlock({ code, language = 'bash' }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => { await navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  return (
    <div className="relative group my-4 rounded-xl overflow-hidden border border-gray-200 dark:border-gray-700 bg-gray-900">
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 text-gray-400 text-xs">
        <span>{language}</span>
        <button onClick={copy} className="hover:text-white transition-colors">{copied ? 'Copied!' : 'Copy'}</button>
      </div>
      <pre className="p-4 overflow-x-auto text-sm font-mono text-gray-100 leading-relaxed">{code}</pre>
    </div>
  );
}
