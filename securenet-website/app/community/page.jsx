import { Github, MessageCircle, Youtube, Calendar } from 'lucide-react';

const channels = [
  [Github, 'GitHub', 'Star the repo, report bugs, submit PRs.', 'https://github.com/SecureAgentNet/secure-agent-net'],
  [MessageCircle, 'Discussions', 'Get help and share setups.', 'https://github.com/SecureAgentNet/secure-agent-net/discussions'],
  [Youtube, 'YouTube', 'Tutorials, deep-dives, demos.', '#'],
  [Calendar, 'Events', 'Monthly calls, CTF competitions.', '#'],
];

export default function CommunityPage() {
  return (
    <>
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h1 className="text-4xl font-extrabold">Join the Community</h1>
          <p className="mt-4 text-lg text-gray-600">Help shape the future of AI agent security.</p>
        </div>
      </section>
      <section className="py-16 bg-white">
        <div className="max-w-4xl mx-auto px-4 grid sm:grid-cols-2 gap-5">
          {channels.map(([Icon, title, desc, href]) => (
            <a key={title} href={href} className="p-6 rounded-xl border border-gray-200 bg-slate-50 hover:border-blue-300 transition-colors">
              <Icon className="w-7 h-7 text-blue-600 mb-3" />
              <h3 className="font-bold">{title}</h3>
              <p className="text-sm text-gray-600 mt-1">{desc}</p>
            </a>
          ))}
        </div>
      </section>
    </>
  );
}
