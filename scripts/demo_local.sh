#!/usr/bin/env bash
# Local "Webroot for AI agents" demo: one Cloud Console + several endpoints
# (real daemons on different ports/data-dirs), each enrolled and reporting.
# Drives a blocked attack on one endpoint so it surfaces in the console.
#
#   ./scripts/demo_local.sh start   # bring the fleet up (default)
#   ./scripts/demo_local.sh stop    # tear it all down
#
# Then open the dashboard URL it prints. To sign in use the admin creds below.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/venv/bin/python"
SAN="$ROOT/venv/bin/secureagentnet"
CLOUD="$ROOT/venv/bin/secureagentnet-cloud"
DAEMON="$ROOT/venv/bin/secureagentnet-daemon"
DEMO="/tmp/san-local-demo"

CONSOLE_PORT=8800
CONSOLE_URL="http://127.0.0.1:${CONSOLE_PORT}"
ADMIN_EMAIL="admin@san.local"
ADMIN_PW="demo123"
# name:port pairs — each is a separate "machine"
ENDPOINTS=("laptop-1:17541" "server-2:17542" "ci-runner-3:17543")

jget() { "$PY" -c "import sys,json;print(json.load(sys.stdin)$1)"; }

stop() {
  echo "Stopping demo…"
  for pidf in "$DEMO"/*.pid "$DEMO"/*/daemon.pid; do
    [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null
  done
  echo "Stopped. (data left in $DEMO)"
}

start() {
  command -v "$CLOUD" >/dev/null 2>&1 || { echo "Run 'pip install -e .' first."; exit 1; }
  rm -rf "$DEMO"; mkdir -p "$DEMO"

  # ── 1. Cloud Console ───────────────────────────────────────────
  export SAN_CLOUD_DATABASE_URL="sqlite:///$DEMO/console.db"
  export SAN_CLOUD_SECRET_KEY="$("$PY" -c 'import secrets;print(secrets.token_hex(32))')"
  export SAN_CLOUD_ADMIN_EMAIL="$ADMIN_EMAIL"
  export SAN_CLOUD_ADMIN_PASSWORD="$ADMIN_PW"
  echo "▸ Starting Cloud Console on $CONSOLE_URL …"
  "$CLOUD" --port "$CONSOLE_PORT" > "$DEMO/console.log" 2>&1 &
  echo $! > "$DEMO/console.pid"
  for i in $(seq 1 20); do
    curl -s --max-time 2 "$CONSOLE_URL/health" >/dev/null 2>&1 && break; sleep 1
  done

  local TOKEN
  TOKEN="$(curl -s -X POST "$CONSOLE_URL/api/v1/admin/login" -H 'Content-Type: application/json' \
            -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PW\"}" | jget "['access_token']")"
  [ -n "$TOKEN" ] || { echo "Console login failed; see $DEMO/console.log"; exit 1; }

  # ── 2. Endpoints: enroll + launch a real daemon each ───────────
  for spec in "${ENDPOINTS[@]}"; do
    local name="${spec%%:*}" port="${spec##*:}"
    local dd="$DEMO/$name"; mkdir -p "$dd/data"
    local et
    et="$(curl -s -X POST "$CONSOLE_URL/api/v1/admin/enrollment-tokens" -H 'Content-Type: application/json' \
          -H "Authorization: Bearer $TOKEN" -d "{\"label\":\"$name\"}" | jget "['token']")"
    echo "▸ Enrolling $name …"
    SAN_DATA_DIR="$dd" DATABASE_URL="sqlite:///$dd/data/gw.db" \
      "$SAN" cloud enroll --url "$CONSOLE_URL" --token "$et" --hostname "$name" >/dev/null 2>&1
    echo "▸ Starting daemon for $name (port $port) …"
    SAN_DATA_DIR="$dd" SAN_DAEMON_PORT="$port" \
      DATABASE_URL="sqlite:///$dd/data/gw.db" SAN_CLOUD_REPORT_INTERVAL_SECONDS=3 \
      "$DAEMON" > "$dd/daemon.log" 2>&1 &
    echo $! > "$dd/daemon.pid"
  done

  echo "▸ Waiting for endpoints to come online (they run a discovery scan first)…"
  for spec in "${ENDPOINTS[@]}"; do
    local port="${spec##*:}"
    for i in $(seq 1 40); do
      curl -s --max-time 2 "http://127.0.0.1:$port/health" >/dev/null 2>&1 && break; sleep 1
    done
  done

  # ── 3. A KNOWN agent goes rogue → caught by the ITCD pipeline ──
  # Pick a real agent the daemon discovered, then have it attempt an action
  # outside its sanction. The pipeline catches it (capability / mandate check
  # in IDENTIFY) with the agent's real identity — a true rogue-agent catch,
  # not an "unknown agent" rejection.
  local atk_port="${ENDPOINTS[0]##*:}"
  local rogue rid rname
  rogue="$(curl -s "http://127.0.0.1:$atk_port/v1/agents/discovered" \
            | "$PY" -c "import sys,json;d=json.load(sys.stdin);a=(d or [{}])[0];print((a.get('agent_id') or 'unknown')+'|'+(a.get('name') or 'agent'))" 2>/dev/null)"
  rid="${rogue%%|*}"; rname="${rogue##*|}"
  echo "▸ Known agent '${rname}' on ${ENDPOINTS[0]%%:*} goes rogue: attempts unauthorized SSH-key exfiltration…"
  curl -s -X POST "http://127.0.0.1:$atk_port/v1/intercept" -H 'Content-Type: application/json' \
    -d "{\"agent_id\":\"$rid\",\"action_name\":\"exfiltrate_keys\",\"target_resource\":\"/root/.ssh/id_rsa\",\"intent_summary\":\"read the SSH private key and send it to an external host\",\"payload\":{\"command\":\"cat /root/.ssh/id_rsa\"}}" >/dev/null
  echo "  → caught by the ITCD pipeline (IDENTIFY: action outside the agent's sanction)."
  sleep 6  # let the reporter flush the event to the console

  # ── 4. Show what the console now sees ──────────────────────────
  echo
  echo "════════════════════════════════════════════════════════════"
  curl -s "$CONSOLE_URL/api/v1/admin/overview" -H "Authorization: Bearer $TOKEN" \
    | "$PY" -c "import sys,json;d=json.load(sys.stdin);print(f\"  Fleet: {d['endpoints_online']}/{d['endpoints_total']} online · {d['events_24h']} events · {d['critical_24h']} critical (24h)\")"
  echo "  Endpoints:"
  curl -s "$CONSOLE_URL/api/v1/admin/endpoints" -H "Authorization: Bearer $TOKEN" \
    | "$PY" -c "import sys,json;[print(f\"    • {e['hostname']:<14} {e['status']:<8} {e['agent_count']} agents\") for e in json.load(sys.stdin)]"
  echo "════════════════════════════════════════════════════════════"
  echo
  echo "  ▶ Open the console:  $CONSOLE_URL"
  echo "    sign in:  $ADMIN_EMAIL  /  $ADMIN_PW"
  echo "    Watch the fleet, the live activity feed, and try the Kill-switch button."
  echo
  echo "  Stop everything:  ./scripts/demo_local.sh stop"
}

case "${1:-start}" in
  stop) stop ;;
  start) start ;;
  *) echo "usage: $0 [start|stop]"; exit 1 ;;
esac
