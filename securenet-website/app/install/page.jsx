import Link from 'next/link';

const steps = [
  ['brew', 'Homebrew (macOS/Linux)', `brew tap SecureAgentNet/tap\nbrew install secureagentnet\nsecureagentnet --version\nsecureagentnet init`],
  ['pip', 'pip (Any OS)', `pip install secureagentnet\nexport DEPLOY_MODE=minimal\nsecureagentnet init --mode minimal\nsecureagentnet doctor`],
  ['docker', 'Docker', `curl -O https://raw.githubusercontent.com/SecureAgentNet/secure-agent-net/main/deployment/docker-compose.prod.yml\ndocker compose up -d`],
  ['curl', 'One-liner', `curl -fsSL https://raw.githubusercontent.com/SecureAgentNet/secure-agent-net/main/scripts/install.sh | sh`],
];

export default function InstallPage() {
  return (
    <>
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white">
        <div className="max-w-3xl mx-auto px-4 text-center">
          <h1 className="text-4xl font-extrabold">Install SecureAgentNet</h1>
          <p className="mt-4 text-lg text-gray-600">Up and running in under 5 minutes. Works on Linux, macOS, and Windows.</p>
          <div className="mt-6 p-4 rounded-xl bg-amber-50 border border-amber-200 text-left text-sm text-amber-800">
            <strong>Prerequisites:</strong> Python 3.10+ · Docker 24+ (optional) · 4 GB RAM
          </div>
        </div>
      </section>
      <section className="py-16 bg-white">
        <div className="max-w-3xl mx-auto px-4 space-y-10">
          {steps.map(([id, title, code]) => (
            <div key={id}>
              <h2 className="text-xl font-bold mb-3">{title}</h2>
              <pre className="bg-gray-900 text-green-400 p-5 rounded-xl text-sm font-mono overflow-x-auto leading-relaxed">{code}</pre>
            </div>
          ))}
        </div>
      </section>
      <section className="py-16 bg-slate-50 text-center">
        <h2 className="text-2xl font-bold mb-4">Troubleshooting</h2>
        <p className="text-sm text-gray-500 max-w-xl mx-auto">
          Command not found? Check PATH includes /usr/local/bin. Docker not responding? Launch Docker Desktop. Still stuck?{' '}
          <a href="https://github.com/SecureAgentNet/secure-agent-net/issues" className="text-blue-600 hover:underline">Open an issue</a>.
        </p>
      </section>
    </>
  );
}
