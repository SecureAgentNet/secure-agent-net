# SecureAgentNet Website

Production-grade marketing and documentation site built with Next.js 14 + Tailwind CSS.

## Quick Start

```bash
cd securenet-website
npm install
npm run dev        # http://localhost:3000
npm run build      # static export to out/
```

## Pages

| Route | Description |
|-------|-------------|
| `/` | Landing page — hero, pipeline diagram, features, quickstart |
| `/install` | 5-tab installer (brew, pip, docker, source, curl) with troubleshooting |
| `/docs` | Documentation hub with sidebar categories |
| `/features` | 10 enterprise-grade security features |
| `/architecture` | ITCD pipeline deep-dive, technology stack, deployment modes |
| `/pricing` | Free/open-source + Managed Cloud + Enterprise tiers |
| `/community` | GitHub, Slack, YouTube, events |
| `/about` | Mission, origin story, open-source commitment |
| `/blog` | Technical blog posts with tag filtering |

## Deploy to Vercel

1. Push to GitHub
2. Go to [vercel.com](https://vercel.com) → Import Project
3. Set **Root Directory** to `securenet-website`
4. Framework: **Next.js** (auto-detected)
5. Deploy

## Tech Stack

- Next.js 14 (static export)
- Tailwind CSS 3.4
- Framer Motion (animations)
- Lucide React + Heroicons (icons)
