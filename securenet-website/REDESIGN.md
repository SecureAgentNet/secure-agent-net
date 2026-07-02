# SAN Website Overhaul — Design Plan

Decisions made 2026-06-12 (discovery Q&A). Scope: **homepage perfection first**,
other pages get a light pass to match. Stack stays Astro + Tailwind.

## Direction summary

| Decision | Choice |
|---|---|
| Audience | Developers & adopters (examiners served by `/evaluation` one click away) |
| Visual direction | Premium SaaS polish — Linear/Vercel-grade restraint |
| Hero centerpiece | Scroll-driven interactive ITCD pipeline story |
| Palette | Refined dark + cyan: near-black surfaces, one disciplined accent |
| Typography | Keep Space Grotesk / Inter / JetBrains Mono; enforce a strict scale |
| Motion & 3D | Drop three.js mesh; CSS-only motion + gradient horizon + grain |
| Homepage narrative | Threat → proof → product |
| Signature visual | Styled terminal session (real CLI flow, kept truthful) |
| Primary CTA | Copyable `pip install secureagentnet` one-liner |

## Design system changes (global.css + tailwind.config.mjs)

1. **Surfaces** — collapse to 3 levels: `#0a0a0c` page, `#101014` raised,
   `#16161c` interactive. Kill the busy glass blur where it doesn't earn its
   contrast cost; borders `white/8` resting, `white/14` hover.
2. **Accent discipline** — cyan (`#4cd7f6`) is the ONLY brand accent on
   marketing surfaces. Green = success/allow, red = deny, amber = escalate —
   used exclusively for decision semantics, never decoration.
3. **Type scale** — exactly 6 sizes (12/14/16/20/32/56-clamp). Display headlines:
   Space Grotesk, `tracking-[-0.03em]`, `leading-[1.05]`. Remove all
   intermediate one-off sizes.
4. **Motion** — one easing (`cubic-bezier(.22,1,.36,1)`), 200ms micro /
   600ms section reveals, scroll-driven pipeline via IntersectionObserver +
   CSS custom properties. `prefers-reduced-motion` honored everywhere.
5. **Texture** — fixed soft radial gradient horizon behind the hero
   (cyan 4% → transparent) + 2% noise grain overlay. Delete `HeroMesh.astro`
   and the `three` dependency (≈600KB saved).

## Homepage spec (threat → proof → product)

### 1. Hero (above the fold)
- H1: short, confident (working copy: "The firewall for AI agents." —
  subhead carries the zero-trust/ITCD detail).
- Copyable `pip install secureagentnet` pill with copy button + "Read the docs"
  ghost link. GitHub stars chip in nav.
- **Verify before ship:** is the package actually on PyPI? If not, CTA becomes
  `pip install git+https://github.com/...` until published.

### 2. Scroll-driven ITCD pipeline story (the centerpiece)
Pinned viewport section, ~4 viewport-heights of scroll distance, one beat per phase.
A single request — `transfer_funds → acct 0xATTACKER` from a hijacked payroll
agent — travels a horizontal pipeline:
- **IDENTIFY** — identity card flips in: signature ✓, trust 50, capabilities listed.
- **TRACK** — log lines typewrite: reasoning captured, Vault-signed receipt hash.
- **CONTAIN** — sandbox wireframe wraps the payload: seccomp, read-only rootfs, no network.
- **DECIDE** — mandate comparison renders ("Pay employee salaries" vs action),
  risk meter sweeps to 1.0, **red BLOCKED stamp**, container torn down.
Ends with: "Every action. Every agent. Before execution." + scroll-release.
Implementation: one Astro component, vanilla JS scroll progress → CSS vars,
all states reachable without JS (static final frame as fallback).

### 3. Evidence band (proof)
Current stats band, re-typeset to the new scale: 97.0% / 0% / 6-of-6 / ~2ms
with count-up on reveal; one-line ablation hook (6/6 → 3/6 without mandates);
link to `/evaluation`. Numbers stay sourced from `docs/evaluation/results*.json`.

### 4. Capabilities (product) — four alternating sections
Each = headline + 3 lines of copy + **styled terminal panel** (the signature
visual; shared `<Terminal>` component, real CLI output only):
1. Mandate enforcement — `san agent commission` → hijack → `[BLOCKED]`.
2. MCP tool vetting — `san mcp vet` finding a poisoned tool description.
3. Kernel-hardened sandbox — `san run` showing seccomp/rootfs/network lockdown.
4. Tamper-evident audit — Vault-signed trail + `scripts/verify_audit_log.py` pass.

### 5. Frameworks strip
Keep LangChain / CrewAI / AutoGen cards, restyle flat (no glass), one line each.

### 6. Final CTA
Repeat the copyable install command big. Secondary: GitHub.

## Light pass on other pages (same session, timeboxed)
- Apply new surfaces/type/accent tokens site-wide (they inherit from global.css).
- `/evaluation`: already content-complete — retype to scale, add count-ups.
- `/features`, `/architecture`, `/install`, `/docs`, `/blog`: token sweep only;
  replace glass-heavy panels with flat raised surfaces; no content rewrites.
- Nav: add GitHub star-count chip; keep Evaluation link.

## Build order
1. Design tokens (global.css, tailwind config) + delete three.js → site-wide sweep.
2. `<Terminal>` component.
3. Hero + install CTA.
4. Pipeline scroll story (biggest item — build static frames first, wire scroll last).
5. Evidence band + capabilities + frameworks + final CTA.
6. Light pass on other pages, rebuild, Lighthouse check (target: 95+ perf, no CLS).

## Definition of done
- Homepage tells threat → proof → product in one scroll, no WebGL, CSS-only motion.
- Every number on the site traces to `docs/evaluation/results*.json`.
- Every terminal panel shows output the real CLI can produce.
- Lighthouse ≥95 performance, reduced-motion safe, mobile-first responsive.