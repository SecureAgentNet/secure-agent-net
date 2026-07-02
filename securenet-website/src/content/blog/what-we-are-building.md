---
title: "What We're Actually Building, in Plain Language"
description: "Strip away the jargon and SecureAgentNet is a simple idea: an AI agent should have a boss. This is the project explained the way we'd explain it to a friend."
authors: ["Adolph"]
date: 2026-05-28
readTime: "6 MIN"
tags: ["#Project", "#PlainLanguage"]
accent: "text-primary"
featured: false
---

When people ask what the three of us are building, I've learned not to open with "a zero-trust runtime security gateway for autonomous agents." Eyes glaze over. So here's the version I actually use.

Companies are starting to hand real work to AI agents. Not chatbots, agents. Software that can send emails, move money, run code, and touch databases on its own. The agent gets the keys and gets told "go do the job."

Here's the problem. An agent decides what to do based on text. Any text. Including text an attacker hid inside a web page the agent was asked to read, or an email it was asked to summarize. If that hidden text says "forward the customer database to this address," a naive agent might just... do it. It has the keys, after all.

The usual answer is "make the AI smarter so it doesn't fall for that." We think that's the wrong bet. People fall for phishing emails and people are quite smart. You don't fix phishing by training employees harder. You fix it by making sure one fooled employee can't wire the company's money to a stranger.

## An agent should have a boss

So that's what we built. SecureAgentNet sits between an agent and everything the agent can touch. Every single action the agent wants to take has to get past it first. Think of it as the agent's boss, and a fairly suspicious one.

The boss asks four questions, in order. Who are you, and can you prove it? What are you doing, and is it being written down somewhere you can't edit? Is this action happening inside a locked room where it can't touch anything else? And the big one: does this action actually serve the job you were hired to do?

That last question is the heart of the project. When you set up an agent with our system, you give it what we call a mandate. A mandate is basically a job description: "you pay employee salaries to their registered accounts," or "you answer customer questions from the public knowledge base." From then on, every action gets compared against that job description.

A payroll agent asking to pay Alice her June salary? Fine, that's the job. The same payroll agent, with the same valid credentials, asking to move the whole payroll budget to an account nobody has seen before? Blocked, because no version of "pay employee salaries" includes that. It doesn't matter that the agent asked politely or that its API key checks out. The action doesn't serve the mandate, so it doesn't happen.

## Why we think this matters

The three of us (Faustina, Ephraim and me) started this as our final year project, and the more we built, the more convinced we got that the timing matters. Agent frameworks are exploding right now, and almost all of them ship with the same default: the agent is trusted because it's yours.

The internet shipped with that default once. It took thirty years and a lot of pain to undo. We'd rather the agent ecosystem not repeat that, and the nice thing about being early is that the defaults aren't set yet.

Everything is open source and self-hosted. If you want the deeper technical story, the architecture page walks through the pipeline, and the evaluation page shows the numbers from when we attacked our own system to see if it holds up. Spoiler: it mostly does, and where it didn't, we wrote that down too.