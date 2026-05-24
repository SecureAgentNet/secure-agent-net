'use client';
import { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, AlertTriangle } from 'lucide-react';
import CodeBlock from '@/components/CodeBlock';

const tabs = [
  { id: 'brew', name: 'Homebrew', icon: '🍺', os: 'macOS / Linux' },
  { id: 'pip', name: 'pip', icon: '🐍', os: 'Any OS' },
  { id: 'docker', name: 'Docker', icon: '🐳', os: 'Any OS' },
  { id: 'source', name: 'Source', icon: '📦', os: 'Any OS' },
  { id: 'curl', name: 'curl', icon: '⬇️', os: 'Any OS' },
];

const installContent = {
  brew: `# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add SecureAgentNet tap
brew tap SecureAgentNet/tap

# Install SecureAgentNet
brew install secureagentnet

# Verify
secureagentnet --version
# SecureAgentNet v2.0.0

# Initialize
secureagentnet init
secureagentnet doctor`,
  pip: `# Create virtual environment
python3 -m venv san-env
source san-env/bin/activate

# Install
pip install secureagentnet

# Verify
secureagentnet --version

# Quick start (no Docker needed)
export DEPLOY_MODE=minimal
secureagentnet init --mode minimal
secureagentnet doctor --deploy-mode minimal`,
  docker: `# Download Docker Compose file
curl -fsSL https://raw.githubusercontent.com/SecureAgentNet/secure-agent-net/main/deployment/docker-compose.prod.yml -o docker-compose.yml

# Create .env
curl -fsSL https://raw.githubusercontent.com/SecureAgentNet/secure-agent-net/main/.env.example -o .env

# Start all services
docker compose up -d

# Initialize
docker compose exec securenet secureagentnet db migrate
secureagentnet doctor`,
  source: `# Clone
git clone https://github.com/SecureAgentNet/secure-agent-net.git
cd secure-agent-net

# Create venv
python3 -m venv venv && source venv/bin/activate

# Install editable
pip install -e ".[dev]"

# Initialize
secureagentnet init --mode local
secureagentnet doctor

# Run tests
pytest tests/unit/ tests/red_team/ -v`,
  curl: `# One-liner installer (auto-detects OS)
curl -fsSL https://raw.githubusercontent.com/SecureAgentNet/secure-agent-net/main/scripts/install.sh | sh

# The script:
# - Detects your OS (macOS/Linux/Windows)
# - Installs via brew, pip, or from source
# - Sets up ~/.secureagentnet/
# - Runs secureagentnet init
# - Prints next steps`,
};

const verifications = [
  { cmd: 'secureagentnet --version', expect: 'SecureAgentNet v2.0.0' },
  { cmd: 'secureagentnet doctor --deploy-mode local', expect: 'All checks passed' },
  { cmd: 'secureagentnet init --seed', expect: 'SecureAgentNet initialized' },
  { cmd: "secureagentnet evaluate 'ls -la'", expect: 'Decision: ALLOWED' },
];

const troubleshooting = [
  { issue: 'Command not found: secureagentnet', fix: 'Ensure pip/brew install completed. Check PATH includes /usr/local/bin. Restart terminal.' },
  { issue: 'Cannot connect to Docker daemon', fix: 'Ensure Docker Desktop is running. Linux: sudo systemctl start docker.' },
  { issue: 'Port 5000 already in use', fix: 'Change port: secureagentnet server start --port 5001. Or: lsof -ti:5000 | xargs kill.' },
  { issue: 'Ollama model download stuck', fix: 'Model is ~4GB. Check progress: ollama list. Retry: ollama pull llama3.2:latest.' },
];

export default function InstallPage() {
  const [active, setActive] = useState('brew');

  return (
    <>
      <section className="section bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="container text-center max-w-3xl">
          <motion.h1 className="heading" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>Install SecureAgentNet</motion.h1>
          <motion.p className="subheading mx-auto" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>Up and running in under 5 minutes. Choose your preferred method.</motion.p>
          <motion.div className="mt-6 p-4 rounded-xl bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 text-left" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 shrink-0 mt-0.5" />
              <div className="text-sm text-yellow-800 dark:text-yellow-200">
                <strong>Prerequisites:</strong> Python 3.10+ — Docker 24+ (optional, for sandboxing) — 4 GB RAM — Linux / macOS / Windows
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      <section className="py-12 bg-white dark:bg-dark-bg">
        <div className="container max-w-4xl">
          <div className="flex flex-wrap gap-2 mb-8">
            {tabs.map(t => (
              <button key={t.id} onClick={() => setActive(t.id)} className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${active === t.id ? 'bg-brand-blue text-white shadow' : 'bg-gray-100 dark:bg-dark-surface text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700'}`}>
                {t.icon} {t.name} <span className="text-xs opacity-60 ml-1">({t.os})</span>
              </button>
            ))}
          </div>
          <CodeBlock code={installContent[active]} />
        </div>
      </section>

      <section className="py-16 bg-gray-50 dark:bg-dark-surface">
        <div className="container max-w-4xl">
          <h2 className="heading text-center mb-10">Verify Installation</h2>
          <div className="space-y-4">
            {verifications.map((v, i) => (
              <div key={i} className="flex items-start gap-4 p-4 rounded-xl bg-white dark:bg-dark-bg border border-gray-200 dark:border-gray-800">
                <Check className="w-5 h-5 text-brand-green shrink-0 mt-1" />
                <div>
                  <code className="text-sm bg-gray-100 dark:bg-dark-surface px-2 py-0.5 rounded">{v.cmd}</code>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Expected: {v.expect}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container max-w-4xl">
          <h2 className="heading text-center mb-10">Troubleshooting</h2>
          <div className="space-y-4">
            {troubleshooting.map((t, i) => (
              <div key={i} className="p-4 rounded-xl border border-gray-200 dark:border-gray-800">
                <p className="font-semibold text-sm text-brand-red mb-1">❌ {t.issue}</p>
                <p className="text-sm text-gray-600 dark:text-gray-400">{t.fix}</p>
              </div>
            ))}
          </div>
          <p className="text-center mt-8 text-sm text-gray-500">
            Still stuck? <a href="https://github.com/SecureAgentNet/secure-agent-net/issues" className="text-brand-blue hover:underline">Open a GitHub issue</a> or join our community.
          </p>
        </div>
      </section>
    </>
  );
}
