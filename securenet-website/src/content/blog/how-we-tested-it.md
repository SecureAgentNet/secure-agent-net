---
title: "How We Tested It, and How We Got It Wrong the First Time"
description: "Our first benchmark said the system caught every attack but also blocked a third of normal work. The real story behind that number taught us more than the good results did."
authors: ["Ephraim"]
date: 2026-06-11
readTime: "8 MIN"
tags: ["#Evaluation", "#RedTeam"]
accent: "text-tertiary-container"
featured: false
---

A security system that blocks everything is easy to build and completely useless. The hard part is blocking the attacks while leaving real work alone, so when we evaluated SecureAgentNet we measured both sides from the start.

The setup: 55 attack scenarios mapped to the OWASP Top 10 for LLMs (prompt injection, data exfiltration, excessive agency, the whole catalogue), plus 25 normal, boring requests an agent would actually make on a normal day. Run a sales report. Check the error logs. Read the README. All 80 go through the real gateway, with real LLM calls, no mocks. Attacks should get blocked, normal work should get through.

First full run: every attack blocked. We were pretty pleased with ourselves for about a minute, because the same run also hard-blocked 28% of the normal requests. The system refused to let an agent run unit tests. It treated "get the weather forecast for London" as a threat. A security guard who tackles the staff is not a security guard you keep.

## The bug was in the test, not the system

We spent a while trying to make the evaluator less paranoid before we noticed the actual problem. Our system has a rule we're proud of: an agent that hasn't been commissioned with a mandate is fail-closed and treated as high risk. And in our benign test set, 24 of the 25 normal requests had no mandate attached. We had been asking the system to trust agents that, by our own design, it must never trust.

In other words, the system was doing exactly what we built it to do, and our test was measuring it unfairly. So we fixed the test. Every benign request got the mandate its agent would have in production. And while we were at it we made the attacks harder too: instead of arriving mandate-less and obviously suspicious, every attack now arrives under a plausible cover mandate, the way a real compromised agent would.

After the fix, across three independent runs: detection averaged 97%, and the false positives went to zero. Not one normal request hard-blocked in any run. Detection did drop from the perfect 100%, because the attacks got harder to spot under their cover mandates. We'll take that trade. The first set of numbers flattered us and lied. These ones are smaller and true.

## Breaking our own system on purpose

The other thing we did is what researchers call an ablation, which is a fancy word for removing a part to prove it mattered. Our claim is that the mandate (the agent's commissioned goal) is the load-bearing piece. So we ran the entire benchmark again with mandates stripped out and nothing else changed.

Without mandates, the system stayed "safe" in the dumbest possible way: it escalated 64% of normal work to a human for review, and still only caught half the goal-hijacking attempts. With mandates, normal work flows through untouched and the hijacks go six for six. Same requests, same model, same everything. The job description is what does the work.

We also ran a baseline with just the static rule filter and no LLM at all. It catches 14.5% of attacks. Fast, never wrong about normal work, and blind to anything subtle. The distance between 14.5% and 97% is what the semantic layer earns.

All of it is reproducible. The corpora, the harness, and the raw results ship in the repository, and one command reruns the whole thing on your own hardware. If you get different numbers, we genuinely want to hear about it.