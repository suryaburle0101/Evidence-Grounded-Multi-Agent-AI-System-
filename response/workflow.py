"""Human-reviewed response and post-action validation workflow."""

from __future__ import annotations


def build_workflow(response: dict, risk: dict) -> dict:
    """Create actionable, approval-gated response tasks; never execute controls."""
    actions = response.get("recommended_actions", []) if isinstance(response, dict) else []
    decision = response.get("final_decision") if isinstance(response, dict) else None
    if decision == "BENIGN" or not response.get("requires_action", False):
        state = "monitoring"
    else:
        state = "pending_analyst_approval"
    return {
        "state": state,
        "execution_mode": "simulation_only_after_approval",
        "risk_level": (risk or {}).get("level", "LOW"),
        "tasks": [
            {"id": f"task-{index + 1}", "description": action,
             "status": "proposed", "requires_approval": True}
            for index, action in enumerate(actions)
        ],
        "validation_required": state != "monitoring",
        "validation_states": ["New", "Triaged", "Contained", "Resolved", "False positive"],
    }
