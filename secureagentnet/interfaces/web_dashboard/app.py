import logging
import os
import secrets
from flask import Flask, render_template, request, jsonify, redirect, url_for, session as flask_session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

from secureagentnet.identify.identity_registry import IdentityRegistry
from secureagentnet.identify.rogue_detector import RogueDetector
from secureagentnet.track.log_indexer import LogIndexer
from secureagentnet.track.forensic_query import ForensicQueryEngine
from secureagentnet.track.structured_logger import StructuredLogger, AgentAuditor
from secureagentnet.decide.circuit_breaker import CircuitBreaker
from secureagentnet.contain.resource_manager import ContainerResourceManager
from secureagentnet.core.pipeline import ITCDPipeline
from secureagentnet.utils.redis_client import get_limiter_storage_uri

logger = logging.getLogger("SecureAgentNet.Dashboard")

app = Flask(__name__)
app.secret_key = os.environ.get("DASHBOARD_SECRET_KEY") or secrets.token_hex(32)
CORS(app)

app.config["RATELIMIT_ENABLED"] = os.environ.get("SAN_TESTING") != "1"

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=get_limiter_storage_uri(),
)

pipeline = ITCDPipeline()
rogue_detector = RogueDetector()
structured_logger = StructuredLogger()
auditor = AgentAuditor()
circuit_breaker = CircuitBreaker(failure_threshold=3, time_window_seconds=60, reset_timeout_seconds=120)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if os.environ.get("SAN_TESTING") == "1":
            return f(*args, **kwargs)
        if not flask_session.get("logged_in"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def dashboard():
    summary = ForensicQueryEngine.get_system_summary()
    recent_events = LogIndexer.get_recent(20)
    kill_switch_status = pipeline.kill_switch.get_status()
    container_summary = ContainerResourceManager.get_resource_usage_summary()
    return render_template(
        "dashboard.html",
        summary=summary,
        recent_events=recent_events,
        kill_switch=kill_switch_status,
        containers=container_summary,
    )


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        admin_user = os.environ.get("DASHBOARD_USER", "admin")
        admin_pass = os.environ.get("DASHBOARD_PASSWORD", secrets.token_urlsafe(16))
        if username == admin_user and password == admin_pass:
            flask_session["logged_in"] = True
            flask_session["username"] = username
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    flask_session.clear()
    return redirect(url_for("login_page"))


@app.route("/agents")
@login_required
def agent_list():
    status_filter = request.args.get("status")
    type_filter = request.args.get("type")
    agents = IdentityRegistry.list_agents(status=status_filter, agent_type=type_filter)
    anomaly_scores = rogue_detector.get_all_anomaly_scores()
    return render_template(
        "agent_list.html",
        agents=agents,
        anomaly_scores=anomaly_scores,
    )


@app.route("/agents/<agent_id>")
@login_required
def agent_detail(agent_id):
    report = ForensicQueryEngine.get_agent_report(agent_id)
    anomaly_score = rogue_detector.compute_anomaly_score(agent_id)
    profile = rogue_detector.get_profile_summary(agent_id)
    return render_template(
        "agent_detail.html",
        report=report,
        anomaly_score=anomaly_score,
        profile=profile,
    )


@app.route("/forensics")
@login_required
def forensic_query():
    query = request.args.get("q", "")
    agent_id = request.args.get("agent_id", "")
    phase = request.args.get("phase", "")
    severity = request.args.get("severity", "")

    events = []
    if query:
        events = ForensicQueryEngine.search_events(query)
    elif agent_id:
        events = ForensicQueryEngine.query_agent_timeline(agent_id)
    elif phase:
        from secureagentnet.core.constants import PipelinePhase
        try:
            phase_enum = PipelinePhase(phase)
            events = LogIndexer.query_by_phase(phase_enum)
        except ValueError:
            pass
    else:
        events = LogIndexer.get_recent(100)

    phase_counts = LogIndexer.count_by_phase()
    severity_counts = LogIndexer.count_by_severity()

    return render_template(
        "forensic_query.html",
        events=events,
        phase_counts=phase_counts,
        severity_counts=severity_counts,
        query=query,
        agent_id=agent_id,
        phase_param=phase,
        severity_param=severity,
    )


@app.route("/security")
@login_required
def security_status():
    ks_status = pipeline.kill_switch.get_status()
    cb_status = {
        "agents_tracked": len(circuit_breaker._state_store),
        "states": {k: v["state"] for k, v in circuit_breaker._state_store.items()},
    }
    anomaly_scores = rogue_detector.get_all_anomaly_scores()
    return render_template(
        "security.html",
        kill_switch=ks_status,
        circuit_breaker=cb_status,
        anomaly_scores=anomaly_scores,
    )


@app.route("/api/agents", methods=["GET"])
@login_required
def api_list_agents():
    agents = IdentityRegistry.list_agents()
    return jsonify(agents)


@app.route("/api/agents", methods=["POST"])
@login_required
def api_register_agent():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400
    agent = IdentityRegistry.register_agent(data)
    return jsonify(agent), 201


@app.route("/api/agents/<agent_id>", methods=["GET"])
@login_required
def api_get_agent(agent_id):
    agent = IdentityRegistry.get_agent(agent_id)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    return jsonify(agent)


@app.route("/api/agents/<agent_id>", methods=["PUT"])
@login_required
def api_update_agent(agent_id):
    data = request.get_json()
    try:
        updated = IdentityRegistry.update_agent(agent_id, data)
        return jsonify(updated)
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/agents/<agent_id>", methods=["DELETE"])
@login_required
def api_delete_agent(agent_id):
    try:
        IdentityRegistry.revoke_agent(agent_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/pipeline/execute", methods=["POST"])
@login_required
def api_execute_action():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    from secureagentnet.track.models import AgentActionRequest
    req = AgentActionRequest(
        action_name=data.get("action", "read_file"),
        target_resource=data.get("resource", "/tmp/test.txt"),
        intent_summary=data.get("intent", "Testing pipeline"),
        payload={"command": data.get("command", "echo 'hello'")},
    )
    import asyncio
    result = asyncio.run(pipeline.execute_agent_action(
        data.get("agent_id", "agent-007"), req, data.get("command", "echo 'hello'")
    ))
    return jsonify(result)


@app.route("/api/forensics/search", methods=["POST"])
@login_required
def api_forensic_search():
    data = request.get_json()
    query = data.get("query", "") if data else ""
    events = ForensicQueryEngine.search_events(query) if query else []
    return jsonify({"results": events, "total": len(events)})


@app.route("/api/security/kill-switch/activate", methods=["POST"])
@login_required
def api_activate_kill_switch():
    pipeline.kill_switch.record_denial("manual-override")
    return jsonify(pipeline.kill_switch.get_status())


@app.route("/api/security/kill-switch/reset", methods=["POST"])
@login_required
def api_reset_kill_switch():
    pipeline.kill_switch.deactivate("api")
    return jsonify(pipeline.kill_switch.get_status())


@app.route("/api/metrics/summary")
@login_required
def api_metrics_summary():
    return jsonify(ForensicQueryEngine.get_system_summary())


@app.route("/health")
def health_check():
    return jsonify({"status": "healthy", "service": "SecureAgentNet Dashboard"})
