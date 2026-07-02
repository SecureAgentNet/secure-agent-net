from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/api/v1/behavior", tags=["Behavior Graph"])


@router.get("/agents/{agent_id}/graph")
async def get_agent_behavior_graph(agent_id: str):
    from secureagentnet.identify.rogue_detector import get_rogue_detector
    from secureagentnet.identify.identity_registry import IdentityRegistry

    agent = IdentityRegistry.get_agent(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    detector = get_rogue_detector()
    graph = detector.get_transition_graph()
    profile = detector.get_profile_summary(agent_id)
    anomaly_score = detector.compute_anomaly_score(agent_id)

    transitions = {}
    agent_transitions = graph._transitions.get(agent_id, {})
    for (seq, next_act), count in agent_transitions.items():
        key = " → ".join(list(seq) + [next_act])
        transitions[key] = count

    history = list(graph._agent_histories.get(agent_id, []))

    return {
        "agent_id": agent_id,
        "agent_name": agent.get("name", agent_id),
        "trust_score": agent.get("trust_score", 50.0),
        "status": agent.get("status", "unknown"),
        "anomaly_score": anomaly_score,
        "total_requests": profile.get("total_requests", 0),
        "recent_history": history[-10:],
        "transitions": transitions,
        "intrinsic_suspicious": [
            " → ".join(s) for s in graph.INTRINSIC_SUSPICIOUS_SEQUENCES
        ],
    }


@router.get("/summary")
async def get_behavior_summary():
    from secureagentnet.identify.rogue_detector import get_rogue_detector
    from secureagentnet.identify.identity_registry import IdentityRegistry

    detector = get_rogue_detector()
    graph = detector.get_transition_graph()

    agents_data = []
    for aid in detector._profiles:
        agent = IdentityRegistry.get_agent(aid)
        profile = detector.get_profile_summary(aid)
        history = list(graph._agent_histories.get(aid, []))
        agents_data.append({
            "agent_id": aid,
            "agent_name": agent.get("name", aid) if agent else aid,
            "status": agent.get("status", "unknown") if agent else "unknown",
            "total_requests": profile.get("total_requests", 0),
            "anomaly_score": profile.get("anomaly_score", 0.0),
            "recent_history": history[-5:],
            "transitions": len(graph._transitions.get(aid, {})),
        })

    return {
        "agents_tracked": len(detector._profiles),
        "action_distribution": graph.get_action_distribution(),
        "agents": agents_data,
    }
