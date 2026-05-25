"use client";

import Hero from '../components/Hero';
import ArchitectureLines from '../components/ArchitectureLines';
import AgentCarousel from '../components/AgentCarousel';
import { motion } from 'framer-motion';

export default function Home() {
  return (
    <>
      {/* Hero Section */}
      <Hero />

      {/* Architecture Diagram */}
      <section className="py-12 bg-gray-100">
        <div className="max-w-4xl mx-auto px-4">
          <ArchitectureLines />
        </div>
      </section>

      {/* Agent Showcase Carousel */}
      <AgentCarousel />

      {/* Call‑to‑Action */}
      <section className="py-16 bg-gradient-primary text-center text-white">
        <h2 className="text-3xl font-bold mb-4">Ready to secure your agents?</h2>
        <p className="mb-6">Free, open‑source, and ready in minutes.</p>
        <div className="flex justify-center gap-4">
          <motion.a
            href="/install"
            className="px-6 py-3 bg-white text-gray-900 rounded-lg font-semibold hover:bg-gray-200"
            whileHover={{ scale: 1.05 }}
          >
            Get Started
          </motion.a>
          <motion.a
            href="/docs"
            className="px-6 py-3 border border-white rounded-lg font-semibold hover:bg-white hover:bg-opacity-10"
            whileHover={{ scale: 1.05 }}
          >
            Read the Docs
          </motion.a>
        </div>
      </section>
    </>
  );
}
