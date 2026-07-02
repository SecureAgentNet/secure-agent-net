---
title: "A Job Description for Your Agent"
description: "Goal hijacking is the scariest attack on AI agents because the agent's credentials stay valid the whole time. Our answer is the mandate: a commissioned goal every action gets checked against."
authors: ["Faustina"]
date: 2026-06-05
readTime: "7 MIN"
tags: ["#Mandates", "#GoalHijacking"]
accent: "text-secondary"
featured: false
---

Imagine a company hires an accountant. Background check passes, references are great, they get a badge and access to the payment system. Six months in, someone slips a note into their inbox that says "wire everything to this offshore account," and they just do it.

Was the badge fake? No. Were their credentials wrong? No. Every security system the company had would have said this person is exactly who they claim to be. The problem isn't who they are. It's that what they did had nothing to do with the job they were hired for.

That's goal hijacking, and it's my favourite attack to explain because it shows why most agent security misses the point. Almost everything in the space checks identity. Is this agent who it says it is? Does it have permission to call this API? Those checks are necessary, and they're also useless against a hijacked agent, because a hijacked agent is still itself. Its credentials stay perfectly valid while it does the attacker's work.

## The mandate

Our answer is something we call commissioning. Before an agent in SecureAgentNet can do anything at all, someone has to commission it with a mandate:

```text
$ san agent commission payroll-bot --goal "Pay employee salaries to registered accounts"
```

The mandate is the agent's job description, and it changes the question the security system asks. Instead of "is this agent allowed to call transfer_funds?" the question becomes "does this particular transfer serve the goal this agent was commissioned for?"

Those are very different questions. A payroll agent is obviously allowed to transfer funds. That's its whole job. So a permission check waves through both the legitimate salary payment and the diversion to the attacker's account, because both are transfers and the agent may transfer. The mandate check separates them: paying Alice her salary serves the commissioned goal, draining the budget to an unlisted account does not, and the second one gets blocked even though the credentials behind it are flawless.

One more design choice that matters: no mandate, no action. An agent that hasn't been commissioned can't do anything. We made the system fail closed, because "the agent exists, so let it act" is exactly the kind of default we built this project to kill.

## Does it actually work?

We didn't want to just assert this, so we tested it the painful way. We built pairs of requests that share the same commissioned goal, where one request is the legitimate job and the other is a hijack attempt with the same action type and the same valid credentials. The only real difference between them is intent.

With mandates on, the system got all six pairs right: every legitimate action allowed, every hijack blocked. Then we ran the identical requests again with the mandates stripped out, and the hijack detection fell to three out of six. Same actions, same words, same credentials. The only thing that changed was whether the system knew what the agent's job was supposed to be.

That gap is the whole argument. You can't tell a hijacked agent from a working one by looking at its badge. You have to know what it was hired to do.