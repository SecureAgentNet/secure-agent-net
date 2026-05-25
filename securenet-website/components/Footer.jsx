import Link from 'next/link';

export default function Footer() {
  return (
    <footer className="bg-gray-900 text-gray-300 py-8">
      <div className="max-w-4xl mx-auto px-4 flex flex-col md:flex-row justify-between items-center">
        <p className="text-sm">© 2026 SecureAgentNet. All rights reserved.</p>
        <div className="flex space-x-4 mt-4 md:mt-0">
          <Link href="https://github.com/SecureAgentNet/secure-agent-net" className="hover:text-white transition-colors">
            GitHub
          </Link>
          <Link href="/privacy" className="hover:text-white transition-colors">
            Privacy
          </Link>
          <Link href="/terms" className="hover:text-white transition-colors">
            Terms
          </Link>
        </div>
      </div>
    </footer>
  );
}
