# Local Cloud-Console Demo ("Webroot for AI agents")

Run the whole central-console story on one machine: one Cloud Console plus three
"endpoints" (real daemons on different ports), each enrolled and reporting metadata
up to the console. This is the local stand-in for the VPS deployment (Phase 3.7).

## Prerequisites

```bash
pip install -e .                         # installs secureagentnet + entry points
( cd console-dashboard && npm install && npm run build )   # builds the dashboard once
```

The dashboard build outputs into `secureagentnet/cloud/dashboard/`, which the console
serves automatically. (If you skip it, the API still works; only the web UI is absent.)

## Run it

```bash
./scripts/demo_local.sh start
```

This brings up, on your machine:

- the **Cloud Console** at `http://127.0.0.1:8800`
- three daemons — **laptop-1**, **server-2**, **ci-runner-3** — each enrolled to the
  console (distinct hostnames via `san cloud enroll --hostname`), reporting heartbeats
  and agent inventory every few seconds
- one **blocked attack** driven on `laptop-1` (a rogue, uncommissioned agent trying to
  read an SSH key → blocked at IDENTIFY → alert forwarded to the console)

It prints a fleet summary and the console URL. Startup takes ~60–90s because each
daemon runs an agent-discovery scan first.

## What to look at

Open **http://127.0.0.1:8800** and sign in with `admin@san.local` / `demo123`:

- **Fleet grid** — three endpoints, online, each with its agent count.
- **Live activity** — the blocked action appears within a few seconds; auto-refreshes.
  Type in the search box to filter (e.g. `exfiltrate`).
- **Endpoint detail** — click a card to see its agents (with trust scores) and events.
- **Kill-switch** — click *Kill-switch* on an endpoint; confirm. The console queues the
  command and the target daemon executes its local kill-switch on the next heartbeat.

## Drive more activity

Each daemon exposes the local intercept API. Send another action to any endpoint
(ports 17541 / 17542 / 17543):

```bash
curl -X POST http://127.0.0.1:17542/v1/intercept -H 'Content-Type: application/json' \
  -d '{"agent_id":"rogue","action_name":"exfiltrate_keys","target_resource":"/etc/shadow",
       "intent_summary":"dump password hashes","payload":{"command":"cat /etc/shadow"}}'
```

For the **goal-hijack money shot** (a CRITICAL alert at risk ≥ 0.7), commission an agent
and have it deviate — this needs a local Ollama model running for the semantic tier:

```bash
SAN_DATA_DIR=/tmp/san-local-demo/laptop-1 san agent commission payroll-bot \
  --goal "Pay employee salaries to registered accounts" --approve-actions transfer_funds
# then intercept a transfer to an unlisted account on that daemon's port
```

## Privacy note (worth showing)

Only **metadata** leaves each host — decisions, risk scores, reasons, agent names/trust,
and a *coarse* target category (`credentials`, `payments`, …), never the raw resource
path or payload. The console's wire contract rejects any non-allowlisted field with HTTP
422, so "data never leaves the host" is enforced, not just promised.

## Stop

```bash
./scripts/demo_local.sh stop
```

## Going to a real VPS later

The same backend ships as `deployment/cloud/{Dockerfile,docker-compose.yml,.env.example}`.
On a VPS: set the secrets in `.env`, `docker compose up -d`, point
`console.secureagentnet.com` at the box, and add TLS (a Caddy reverse proxy). Daemons
then enroll with `san cloud enroll --url https://console.secureagentnet.com --token …`.
