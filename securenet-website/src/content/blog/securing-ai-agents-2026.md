---
title: "AI Agents in 2026: Repeating the Internet's Original Sin"
description: "The internet was built among trusted machines, and security got bolted on decades later. We think the agent ecosystem is being built the same way, and the window to do it differently is short."
authors: ["Adolph", "Faustina", "Ephraim"]
date: 2026-06-02
readTime: "10 MIN"
tags: ["#ZeroTrust", "#AgentSecurity"]
accent: "text-primary"
featured: true
---

In 1969, the first message sent across the ARPANET was supposed to be the word **LOGIN**. The system crashed after two letters, so the internet's first transmission was just "LO". The part of that story people forget is why that early network needed no real security. Everyone on it already knew everyone else. It connected a handful of research institutions staffed by people who trusted one another. You didn't need to authenticate a colleague.

That assumption got poured into the foundation. TCP/IP, standardized in 1983, has no built-in idea of identity or encryption. A packet says where it claims to be from, and the network believes it. For two decades, the answer to "how do we know this traffic is trustworthy?" was basically: it's on our network, so it must be.

The engineers weren't careless. In a small circle of trusted peers, security genuinely looked like a cost with no benefit. Then the network grew to billions of strangers, and the next thirty years went into retrofitting distrust onto a medium designed for trust. SSL arrived in 1995, for a web that had already shipped. SSH replaced telnet only after the damage was visible. Email authentication (SPF, DKIM, DMARC) landed decades after spam and phishing became a tax on everyone. We're still paying that debt down today.

## We are doing it again, with agents

Look at how AI agents are deployed in 2026 and the resemblance is hard to ignore. An agent gets handed an API key, a shell, a browser, and a set of broad OAuth scopes. It gets pointed at a goal and trusted to behave. That's the ARPANET model again: the agent is ours, so it must be trustworthy.

But an agent is not a trusted peer. It's a probabilistic system steered by whatever text enters its context window, including text written by an attacker. The failure modes already have names, and they map onto exploits the web learned about the hard way.

Prompt injection is the agent-era version of an unsanitized input. A malicious instruction hidden in a web page or a document becomes a command the agent executes. Goal hijacking is something like session fixation for reasoning: the agent starts on an approved task and gets steered, mid-flight, toward an action nobody authorized. And confused-deputy attacks are what happen when you give a tool broad scopes and assume good faith, which is exactly the assumption TCP/IP made about a packet's origin.

None of this needs a sophisticated adversary. It only needs us to keep treating an agent's autonomy as a reason to extend it trust.

## Insecure defaults ossify

The lesson of the internet isn't "the engineers should have known better." Plenty of them did. The lesson is that once an ecosystem grows up around an assumption of trust, every later attempt to add security has to fight the entire installed base. We still can't fully retire passwords or unauthenticated email, because the world was built on them first.

The agent ecosystem is in its ARPANET moment right now. The protocols, the tool-calling conventions, the orchestration frameworks are being settled this year. Whatever defaults get chosen now are the defaults a million deployments will inherit. If the default is trust, the 2030s will be spent retrofitting distrust onto agents the way the 2000s were spent retrofitting it onto the web.

## What security by design looks like for agents

The alternative is to assume, from the first line of code, that an agent is untrusted, and to build the gateway that enforces it. That's the premise of SecureAgentNet. Every action an agent attempts passes through a four-phase pipeline we call ITCD before it touches anything real.

**Identify** verifies a signed agent identity and its declared capabilities, and scores its behaviour, before any interaction happens. A packet doesn't get to assert its own origin, and neither does an agent.

**Track** captures the agent's reasoning as it happens and writes it to a tamper-evident, Vault-signed audit trail. If something goes wrong, the record of why is verifiable after the fact.

**Contain** provisions a hardened, ephemeral sandbox (seccomp, AppArmor, read-only root, no network by default) up front, so execution is isolated by construction.

**Decide** runs the request through a layered, fail-closed gateway: fast rule filters, code-intent checks, PII redaction, an LLM risk evaluation, and a human-in-the-loop gate for anything ambiguous. Denied actions never execute.

The ordering matters. Containment is established before the decision is made, so an action only ever runs inside an already-isolated environment. If the gateway denies it, the sandbox is destroyed without executing anything. Nothing is assumed safe because of where it came from.

## The window is open, briefly

The internet got security wrong not because the problem was unsolvable, but because at the founding moment security felt optional. Agents are at that founding moment now. We have the strange advantage of knowing exactly how this story goes if we get it wrong, because we've already lived it once.

We don't have to write "LO" and crash. We can build the trust boundary first this time.