'use client';
import { motion } from 'framer-motion';

export default function AboutPage() {
  return (
    <>
      <section className="section bg-gradient-to-b from-gray-50 to-white dark:from-dark-bg dark:to-dark-surface">
        <div className="container max-w-3xl mx-auto text-center">
          <motion.h1 className="heading" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>About SecureAgentNet</motion.h1>
          <motion.p className="subheading mx-auto" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>Making AI agent security accessible, transparent, and effective for everyone.</motion.p>
        </div>
      </section>
      <section className="py-16 bg-white dark:bg-dark-bg">
        <div className="container max-w-3xl">
          <div className="prose dark:prose-invert max-w-none space-y-8">
            <div>
              <h2 className="text-2xl font-bold mb-4">Our Mission</h2>
              <p className="text-gray-600 dark:text-gray-400 leading-relaxed">
                We believe AI agents have the potential to transform how we work — but only if we can trust them. SecureAgentNet exists to make AI agent security accessible, transparent, and effective for everyone, from individual developers to Fortune 500 companies.
              </p>
            </div>
            <div>
              <h2 className="text-2xl font-bold mb-4">Origin Story</h2>
              <p className="text-gray-600 dark:text-gray-400 leading-relaxed">
                SecureAgentNet began as a final-year Computer Science research project at KNUST (Kwame Nkrumah University of Science and Technology) in Ghana. After witnessing the rapid adoption of AI agents in production systems with little to no security considerations, we set out to build a comprehensive solution. What started as an academic thesis evolved into a mission-critical open-source project.
              </p>
            </div>
            <div>
              <h2 className="text-2xl font-bold mb-4">Open Source Commitment</h2>
              <ul className="space-y-2 text-gray-600 dark:text-gray-400">
                <li>• MIT License — free forever</li>
                <li>• All code on GitHub — transparent development</li>
                <li>• Community-driven roadmap</li>
                <li>• No vendor lock-in — self-host or managed</li>
                <li>• 397 tests, verified on Linux, macOS, and Windows</li>
              </ul>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
