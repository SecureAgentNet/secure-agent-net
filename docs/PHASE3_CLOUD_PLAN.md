# Phase 3 — Cloud Central Console (Webroot model)

_Plan of record. Decisions made 2026-06-23._

The goal: many local SecureAgentNet daemons report **up** to one hosted console, where
an admin sees every endpoint, agent, alert, and audit record across machines — and can
remotely trip an endpoint's kill-switch. "Webroot for AI agents."

## Decisions (locked)

| Question | Choice | Consequence |
|---|---|---|
| Data sent up | **Metadata only** | Decisions, alerts, risk scores, reasons, agent inventory, trust, heartbeats. **No raw payloads, no PII.** Preserves the self-hosted/data-sovereignty story — payload content stays on the host. |
| Console capability | **Observe + remote kill-switch** | Read-only fleet view + exactly one control action (remote kill-switch). Bounded, strong demo. |
| Hosting | **Small cloud VPS** | Always-on backend with a public URL (`console.secureagentnet.com`). NB: secureagentnet.com shared hosting can't run Python — VPS is required. |
| Dashboard stack | **Astro + Tailwind** | On-brand with secureagentnet.com; served by the backend at the console domain (one origin, no CORS). |

## Architecture

```
[Machine A] daemon ─┐
[Machine B] daemon ─┼─ HTTPS push (events) ─►  CLOUD CONSOLE BACKEND (VPS)
[Machine C] daemon ─┘  + heartbeat/command-pull   ├─ FastAPI ingest + admin API
        ▲                                          ├─ Postgres (per-tenant store)
        └────── kill-switch command (pulled) ──────┤─ browser websocket (live)
                                                    └─ serves Astro dashboard (static build)
                                                                │
                                                       Admin browser ◄─ live fleet view
```

### Transport (NAT-friendly, no inbound to daemons)
- **Events:** daemon `POST /api/v1/ingest` in small batches (retried, offline-queued on disk).
- **Heartbeat:** daemon `POST /api/v1/heartbeat` every ~15s; the **response carries any pending commands** (e.g. kill-switch) for that endpoint. This is the control channel — daemons poll, nothing connects inbound to them.
- **Live dashboard:** the *backend* holds a websocket to the *browser* (`/api/v1/stream`), pushed as ingest arrives. (A persistent daemon→cloud websocket is a later optimization; poll-based is simpler and robust for the demo.)

### Privacy enforcement (a selling point, made testable)
A strict **allowlist serializer** on the daemon side builds the outbound payload from an explicit field set (endpoint id, agent ref, action name, target *type*, decision, risk score, reason, severity, timestamps). Raw `payload`/PII fields are structurally unreachable. A unit test asserts no disallowed key ever appears in an outbound report.

## Components & repo layout

1. **Cloud backend** — `secureagentnet/cloud/` (new): FastAPI app, separate Postgres, deployable via its own docker-compose. Reuses crypto/config utilities; its own models (multi-tenant aggregate, distinct from the per-host gateway DB).
2. **Daemon reporting client** — `secureagentnet/daemon/cloud_reporter.py` (new): subscribes to the existing `AlertManager` + decision stream, batches metadata, manages the offline queue + retry + heartbeat loop. Config via `SAN_CLOUD_CONSOLE_URL` + enrolled API key.
3. **Enrollment CLI** — `san cloud enroll --url … --token …` (new CLI group): registers the daemon with a console, stores the endpoint id + API key locally.
4. **Dashboard** — `console-dashboard/` (new Astro+Tailwind project), built static and served by the backend.

## Data model (cloud, tenant-aware from day one)
- **Tenant/Org** — owns endpoints and admin users (single org for the demo; schema ready for more).
- **Endpoint** — a host running a daemon: id, hostname, tenant, status, last_heartbeat, enrolled_at, api_key_hash.
- **AgentSnapshot** — per-endpoint agent inventory mirror: name, type, trust_score, status.
- **Event** — metadata only: endpoint_id, kind (decision|alert|audit), severity, risk_score, reason, agent_ref, action_name, target_type, timestamp.
- **Command** — endpoint_id, type (kill_switch), status (pending|acked|done), issued_by, created_at, acked_at.
- **AdminUser** — console login (start with one admin; bcrypt; session/JWT).

## Auth & the remote-kill-switch trust path
- **Enrollment:** admin generates an enrollment token in the console → daemon `POST /api/v1/enroll {token}` → receives `endpoint_id` + per-daemon API key (stored hashed server-side). All ingest/heartbeat calls carry the key.
- **Remote kill-switch:** admin clicks "Kill" on an endpoint → backend queues a `Command(kill_switch)` for that endpoint → the daemon pulls it on its next heartbeat (authenticated by its API key, scoped to its own endpoint) → executes the **existing local KillSwitchController** → acks. The daemon only ever acts on commands addressed to its own enrolled endpoint id.

## Phased build (3.1 → 3.7), each verified before the next

- **3.1 Backend skeleton** — FastAPI app, models, Postgres, `/health`, docker-compose. Verify: boots, migrations create tables.
- **3.2 Enrollment + auth** — tokens, per-daemon API keys, admin login. Verify: enroll returns a key; protected routes reject unauthenticated calls.
- **3.3 Ingest + heartbeat** — `/api/v1/ingest`, `/api/v1/heartbeat` (with command pull), per-tenant storage + the allowlist serializer + privacy test. Verify: posted metadata lands per-endpoint; no disallowed field stored.
- **3.4 Daemon reporting client** — hook the AlertManager/decision stream, offline queue, retry, heartbeat loop, `san cloud enroll`. Verify: a local block appears in the cloud DB within seconds; survives the backend being down (queue drains on recovery).
- **3.5 Remote kill-switch** — console command → daemon pull → local kill-switch → ack. Verify: clicking Kill in the console halts the target daemon; ack returns.
- **3.6 Dashboard (Astro+Tailwind)** — fleet grid, endpoint detail, live alerts via backend websocket, audit search, kill-switch button. Verify: 2-3 endpoints show live; a hijack on one lights up red in real time.
- **3.7 Deploy** — VPS + docker-compose + Caddy/Let's Encrypt TLS; DNS `console.secureagentnet.com`; end-to-end multi-endpoint demo over the internet.

## Deploy-time prerequisites (need you / the team)
- **A VPS** (Hetzner Cloud / Fly.io / Render) — provider + account + the ~few $/month. I can produce the docker-compose, Caddyfile, and deploy script; you provision the box and share access.
- **DNS** — a `console.secureagentnet.com` A-record at your registrar pointing to the VPS IP.
- **Admin auth depth** — start with a single admin credential (env-seeded); per-user accounts later.

## The demo this produces
Two or three machines (or VMs/containers), each running a daemon enrolled to the console.
The admin opens `console.secureagentnet.com`, sees all endpoints live. A goal-hijack is
attempted on Machine B → it's blocked locally **and** a red CRITICAL alert appears in the
cloud console in real time, trust drops on that endpoint. The admin clicks "Kill" on
Machine C → its daemon halts. That is the Webroot-for-AI-agents story, end to end.
