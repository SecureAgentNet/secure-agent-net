export default function AboutPage() {
  return (
    <>
      <section className="py-20 bg-gradient-to-b from-slate-50 to-white text-center">
        <div className="max-w-3xl mx-auto px-4">
          <h1 className="text-4xl font-extrabold">About SecureAgentNet</h1>
          <p className="mt-4 text-lg text-gray-600">Making AI agent security accessible, transparent, and effective.</p>
        </div>
      </section>
      <section className="py-16 bg-white">
        <div className="max-w-2xl mx-auto px-4 space-y-10 text-gray-700 leading-relaxed">
          <div>
            <h2 className="text-2xl font-bold mb-3">Our Mission</h2>
            <p>AI agents can transform how we work — but only if we trust them. SecureAgentNet makes AI agent security accessible to everyone, from individual developers to Fortune 500 companies.</p>
          </div>
          <div>
            <h2 className="text-2xl font-bold mb-3">Origin</h2>
            <p>SecureAgentNet began as a final-year CS research project at KNUST in Ghana. After seeing AI agents deployed in production with zero security, we built a solution. An academic thesis became an open-source project used worldwide.</p>
          </div>
          <div>
            <h2 className="text-2xl font-bold mb-3">Open Source Commitment</h2>
            <p>MIT licensed, forever. All code on GitHub. Community-driven roadmap. No vendor lock-in. 397 tests, verified on Linux, macOS, and Windows.</p>
          </div>
        </div>
      </section>
    </>
  );
}
