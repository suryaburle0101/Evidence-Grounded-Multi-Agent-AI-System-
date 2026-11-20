"""Load local response-playbook templates and ground steps in incident evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


PLAYBOOK_DIR = Path(__file__).resolve().parent / "playbooks"
PHASES = ("contain", "eradicate", "recover", "verify")


def _family_key(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().casefold()).strip("_")


def _read_template(attack_family: str | None) -> dict[str, Any]:
    key = _family_key(attack_family)
    aliases = {
        "ddos": "ddos",
        "dos": "dos",
        "brute_force": "brute_force",
        "bruteforce": "brute_force",
        "port_scan": "port_scan",
        "portscan": "port_scan",
        "botnet": "botnet",
        "web_attack": "web_attack",
        "webattack": "web_attack",
        "infiltration": "infiltration",
        "heartbleed": "heartbleed",
        "benign": "benign",
    }
    path = PLAYBOOK_DIR / f"{aliases.get(key, 'generic')}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _matches_family(item: dict, family: str, generic: bool) -> bool:
    if generic:
        return True
    value = json.dumps(item.get("value"), ensure_ascii=False, sort_keys=True, default=str)
    haystack = f"{item.get('source', '')} {value}".casefold()
    return family.casefold() in haystack


def build_playbook(attack_family: str | None, evidence_trail: list[dict] | None) -> dict[str, Any]:
    """Build an incident-specific playbook without running its suggested steps."""
    template = _read_template(attack_family)
    evidence_trail = evidence_trail or []
    generic = bool(template.get("generic_playbook"))
    display_family = attack_family or template.get("family", "Unknown")
    phases = []

    for phase_name in PHASES:
        phase_steps = []
        for template_step in template.get("phases", {}).get(phase_name, []):
            allowed_types = set(template_step.get("evidence_types", []))
            evidence_ids = [
                item.get("id")
                for item in evidence_trail
                if item.get("id")
                and item.get("type") in allowed_types
                and item.get("direction") in {"supports ATTACK", "supports BENIGN"}
                and _matches_family(item, str(display_family), generic)
            ]
            if not evidence_ids:
                continue
            phase_steps.append({
                "action": template_step["action"],
                "technique_id": template.get("technique_id"),
                "technique_name": template.get("technique_name"),
                "evidence_ids": evidence_ids,
            })
        phases.append({
            "name": phase_name,
            "steps": phase_steps,
            "status": "ready" if phase_steps else "no_supporting_evidence",
            "empty_reason": "Left empty on purpose: steps must be justified by evidence." if not phase_steps else None,
        })

    return {
        "family": display_family,
        "playbook_label": template.get("playbook_label", "generic playbook"),
        "generic_playbook": generic,
        "technique_id": template.get("technique_id"),
        "technique_name": template.get("technique_name"),
        "knowledge_base_source": template.get("knowledge_base_source"),
        "knowledge_base_reference": template.get("knowledge_base_reference"),
        "knowledge_base_note": template.get("knowledge_base_note"),
        "phases": phases,
        "execution_notice": "Recommendations only. Nothing is executed by this playbook.",
    }
