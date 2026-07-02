---
title: "Contain-First: Why We Sandbox Before We Decide"
description: "Most gateways decide whether to allow an action, then run it. We flipped the order. We isolate first and decide second, and this post explains why."
authors: ["Ephraim", "Adolph"]
date: 2026-05-08
readTime: "7 MIN"
tags: ["#CONTAIN", "#Architecture"]
accent: "text-tertiary-container"
featured: false
---

The obvious way to build a security gateway is to evaluate the request, and if you approve it, run it. Decide, then contain. It's intuitive, and it's what most systems do. For a while it's what ours did too.

SecureAgentNet now runs the ITCD pipeline in its literal order: Identify, Track, Contain, Decide. The sandbox that will run an action is provisioned before the decision is made. It's a small reordering, and it took us a while to appreciate what it buys.

## Isolate before you evaluate

When containment comes last, there's always a sliver of time where an approved-but-not-yet-isolated action exists. Putting Contain before Decide removes that gap. By the time the gateway gives a verdict, the execution environment is already built and already locked down: seccomp and AppArmor profiles applied, a read-only root filesystem, no network by default, resource limits set, secrets injected only for this one run.

The decision then has exactly two outcomes:

```text
IDENTIFY -> TRACK -> CONTAIN(provision) -> DECIDE
  approved? execute in the existing sandbox
  denied?   kill the sandbox, un-executed
```

There's no window where an action runs outside containment, because containment is a precondition of the decision instead of a consequence of it. An action is only ever executed inside an environment that was already isolated when the verdict came in.

## The cost, honestly

This ordering isn't free. Every request that clears the IDENTIFY phase provisions a real container, including ones that DECIDE will go on to deny. We did this on purpose. The IDENTIFY phase already short-circuits the cheap rejections (unknown agents, a tripped kill-switch, missing capabilities, goal-hijack attempts) before any container exists. Only requests that have earned a closer look pay for a sandbox.

Security by construction usually costs something. The question is whether you pay it up front, on purpose, or later, by surprise.