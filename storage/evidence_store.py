"""SQLite-backed local store for knowledge, IOCs, incidents, and events."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = Path(os.environ.get("CYBER_EVIDENCE_DB", ROOT / "data" / "evidence_store.sqlite"))
AUTHORITATIVE_FILE = ROOT / "evidence" / "knowledge" / "authoritative_sources.json"
ATTACK_KNOWLEDGE_FILE = ROOT / "evidence" / "knowledge" / "attack_knowledge.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


INCIDENT_STATES = ("New", "Triaged", "Contained", "Resolved", "False positive")
INCIDENT_TRANSITIONS = {
    "New": ("Triaged", "False positive"),
    "Triaged": ("Contained", "False positive"),
    "Contained": ("Triaged", "Resolved"),
    "Resolved": ("Triaged",),
    "False positive": ("Triaged",),
}
_LEGACY_STATES = {
    "open": "New",
    "in_progress": "Triaged",
    "not_resolved": "Triaged",
    "resolved": "Resolved",
    "false_positive": "False positive",
}


def _canonical_state(value: str) -> str | None:
    normalized = str(value or "").strip().replace("_", " ").casefold()
    for state in INCIDENT_STATES:
        if state.casefold() == normalized:
            return state
    return _LEGACY_STATES.get(str(value or "").strip().casefold())


class EvidenceStore:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def initialize(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT,
                    risk_score REAL,
                    source TEXT,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incidents_updated_idx ON incidents(updated_at);
                CREATE TABLE IF NOT EXISTS validation_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL REFERENCES incidents(id),
                    created_at TEXT NOT NULL,
                    state TEXT NOT NULL,
                    note TEXT,
                    action_taken TEXT
                );
                CREATE TABLE IF NOT EXISTS threat_iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    family TEXT,
                    confidence REAL NOT NULL DEFAULT 0.5,
                    severity TEXT,
                    source TEXT NOT NULL,
                    first_seen TEXT,
                    expires_at TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(indicator_type, indicator_value, source)
                );
                CREATE INDEX IF NOT EXISTS threat_iocs_value_idx ON threat_iocs(indicator_value);
                CREATE TABLE IF NOT EXISTS evidence_documents (
                    id TEXT PRIMARY KEY,
                    family TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    source_name TEXT,
                    source_url TEXT,
                    technique_id TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    incident_id TEXT,
                    payload_json TEXT NOT NULL
                );
            """)
            self._seed_documents(conn)

    @staticmethod
    def _seed_documents(conn):
        sources = json.loads(AUTHORITATIVE_FILE.read_text(encoding="utf-8"))
        knowledge = json.loads(ATTACK_KNOWLEDGE_FILE.read_text(encoding="utf-8"))
        docs = {}
        for source in sources.get("sources", []):
            evidence = source.get("evidence", {})
            text = "\n".join([
                str(evidence.get("description", "")),
                "Indicators: " + "; ".join(evidence.get("indicators", [])),
                "Investigation: " + "; ".join(evidence.get("detection_guidance", [])),
                "Mitigation: " + "; ".join(evidence.get("mitigation_guidance", [])),
            ]).strip()
            doc = {
                "family": source.get("attack_family", "Unknown"),
                "title": source.get("technique_name") or source.get("attack_family", "Attack reference"),
                "body": text,
                "source_name": source.get("source_name"),
                "source_url": source.get("source_url"),
                "technique_id": source.get("technique_id"),
            }
            docs[doc["family"].casefold()] = doc
        for item in knowledge.get("attack_families", []):
            family = item.get("attack", "Unknown")
            extra = "\n".join([
                str(item.get("description", "")),
                "Indicators: " + "; ".join(item.get("indicators", [])),
                "Investigation: " + "; ".join(item.get("investigation", [])),
                "Mitigation: " + "; ".join(item.get("mitigation", [])),
            ])
            key = family.casefold()
            if key in docs:
                docs[key]["body"] += "\n" + extra
            else:
                refs = item.get("sources", [])
                docs[key] = {
                    "family": family,
                    "title": family + " investigation reference",
                    "body": extra,
                    "source_name": refs[0].get("name") if refs else "Local attack knowledge base",
                    "source_url": None,
                    "technique_id": item.get("mitre_attack", {}).get("technique_id"),
                }
        for doc in docs.values():
            doc_id = f"{doc['family'].casefold()}:{doc.get('technique_id') or 'local'}"
            conn.execute("""
                INSERT INTO evidence_documents
                (id,family,title,body,source_name,source_url,technique_id,updated_at)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET title=excluded.title,body=excluded.body,
                source_name=excluded.source_name,source_url=excluded.source_url,
                technique_id=excluded.technique_id,updated_at=excluded.updated_at
            """, (doc_id, doc["family"], doc["title"], doc["body"],
                  doc.get("source_name"), doc.get("source_url"),
                  doc.get("technique_id"), _now()))

    def add_iocs(self, entries: list[dict], default_source: str = "manual") -> int:
        accepted = 0
        with self._connect() as conn:
            for item in entries:
                value = str(item.get("value", "")).strip().casefold()
                kind = str(item.get("type", "unknown")).strip().casefold()
                if not value or not kind:
                    continue
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.5))))
                conn.execute("""
                    INSERT INTO threat_iocs
                    (indicator_type,indicator_value,family,confidence,severity,source,first_seen,expires_at,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(indicator_type,indicator_value,source) DO UPDATE SET
                    family=excluded.family,confidence=excluded.confidence,severity=excluded.severity,
                    first_seen=excluded.first_seen,expires_at=excluded.expires_at
                """, (kind, value, item.get("family"), confidence, item.get("severity"),
                      str(item.get("source") or default_source), item.get("first_seen"),
                      item.get("expires_at"), _now()))
                accepted += 1
        return accepted

    def match_iocs(self, flow) -> list[dict]:
        candidates = {}
        if hasattr(flow, "to_dict"):
            flow = flow.to_dict()
        if not isinstance(flow, dict):
            return []
        field_types = {
            "source ip": "ip", "src ip": "ip", "src_ip": "ip", "source_ip": "ip",
            "destination ip": "ip", "dst ip": "ip", "dst_ip": "ip", "destination_ip": "ip",
            "domain": "domain", "hostname": "domain", "host": "domain",
            "url": "url", "uri": "url", "md5": "hash", "sha1": "hash", "sha256": "hash",
        }
        for key, value in flow.items():
            kind = field_types.get(str(key).strip().casefold())
            if kind and value is not None and str(value).strip():
                candidates[str(value).strip().casefold()] = kind
        if not candidates:
            return []
        matches = []
        now = _now()
        with self._connect() as conn:
            for value, kind in candidates.items():
                rows = conn.execute("""
                    SELECT * FROM threat_iocs WHERE indicator_value=?
                    AND indicator_type IN (?, 'unknown')
                    AND (expires_at IS NULL OR expires_at > ?)
                """, (value, kind, now)).fetchall()
                matches.extend(dict(row) for row in rows)
        return matches

    def save_incident(self, payload: dict, source: str = "pipeline") -> str:
        incident_id = str(uuid.uuid4())
        created = _now()
        risk = payload.get("risk", {})
        severity = risk.get("severity") or payload.get("investigation", {}).get("severity")
        risk_score = risk.get("score")
        payload_to_save = {**payload, "incident_id": incident_id}
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO incidents(id,created_at,updated_at,status,severity,risk_score,source,payload_json)
                VALUES(?,?,?,?,?,?,?,?)
            """, (incident_id, created, created, "New", severity, risk_score,
                  source, json.dumps(payload_to_save, ensure_ascii=False, default=str)))
            conn.execute("INSERT INTO system_events(created_at,event_type,incident_id,payload_json) VALUES(?,?,?,?)",
                         (created, "incident.created", incident_id, json.dumps({"decision": payload.get("final_decision")})))
        return incident_id

    def get_incident(self, incident_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return self._incident_row(row) if row else None

    @staticmethod
    def _incident_row(row) -> dict:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        current_state = _canonical_state(item.get("status"))
        if current_state:
            item["status"] = current_state
            item["allowed_transitions"] = list(INCIDENT_TRANSITIONS[current_state])
        else:
            item["allowed_transitions"] = []
        return item

    def list_incidents(self, limit: int = 100, status: str | None = None) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as conn:
            if status:
                canonical = _canonical_state(status)
                matching = [status]
                if canonical:
                    matching.extend(key for key, value in _LEGACY_STATES.items() if value == canonical)
                    matching.append(canonical.casefold().replace(" ", "_"))
                placeholders = ",".join("?" for _ in matching)
                rows = conn.execute(
                    f"SELECT * FROM incidents WHERE lower(status) IN ({placeholders}) ORDER BY created_at DESC LIMIT ?",
                    (*[value.casefold() for value in matching], limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._incident_row(row) for row in rows]

    def correlate_incidents(self, window_minutes: int = 60, limit: int = 500) -> dict:
        """Find candidate incident groups sharing an endpoint within a time window.

        This is an analyst aid, not proof that records belong to the same campaign.
        It uses ingestion timestamps because source capture timestamps can be absent
        or use incompatible time zones across datasets.
        """
        window_minutes = max(1, min(int(window_minutes), 10080))
        incidents = self.list_incidents(limit=max(2, min(int(limit), 1000)))
        by_endpoint: dict[str, list[dict]] = {}
        for item in incidents:
            context = item.get("payload", {}).get("flow_context", {})
            for role in ("source_ip", "destination_ip"):
                value = context.get(role)
                if value:
                    key = str(value).strip().casefold()
                    by_endpoint.setdefault(key, []).append({"incident": item, "role": role})

        groups = []
        window_seconds = window_minutes * 60
        for endpoint, entries in by_endpoint.items():
            unique = {entry["incident"]["id"]: entry["incident"] for entry in entries}
            if len(unique) < 2:
                continue
            ordered = sorted(unique.values(), key=lambda row: row["created_at"])
            # Sliding window creates compact, time-bounded association groups.
            for start in range(len(ordered)):
                left = ordered[start]
                left_time = datetime.fromisoformat(left["created_at"].replace("Z", "+00:00"))
                members = []
                for candidate in ordered[start + 1:]:
                    right_time = datetime.fromisoformat(candidate["created_at"].replace("Z", "+00:00"))
                    if (right_time - left_time).total_seconds() > window_seconds:
                        break
                    members.append(candidate)
                if members:
                    group_rows = [left, *members]
                    roles = sorted({entry["role"] for entry in entries
                                    if entry["incident"]["id"] in {row["id"] for row in group_rows}})
                    groups.append({
                        "shared_endpoint": endpoint,
                        "relation": "shared_flow_endpoint",
                        "endpoint_roles_seen": roles,
                        "window_minutes": window_minutes,
                        "incident_ids": [row["id"] for row in group_rows],
                        "count": len(group_rows),
                        "first_seen": group_rows[0]["created_at"],
                        "last_seen": group_rows[-1]["created_at"],
                        "families": sorted({str(row["payload"].get("final_attack") or "Unknown")
                                             for row in group_rows}),
                    })
        # Deduplicate overlapping sliding windows; keep the largest group per endpoint.
        best = {}
        for group in groups:
            current = best.get(group["shared_endpoint"])
            if current is None or group["count"] > current["count"]:
                best[group["shared_endpoint"]] = group
        result = sorted(best.values(), key=lambda group: (-group["count"], group["shared_endpoint"]))
        return {
            "groups": result,
            "incidents_scanned": len(incidents),
            "window_minutes": window_minutes,
            "interpretation": "Candidate associations based on a shared endpoint and ingestion time; analyst review is required.",
        }

    def validate_incident(self, incident_id: str, state: str, note: str = "", action_taken: str = "") -> dict | None:
        target_state = _canonical_state(state)
        if target_state not in INCIDENT_STATES:
            raise ValueError("state is not a supported incident lifecycle state")
        now = _now()
        with self._connect() as conn:
            found = conn.execute("SELECT id,status,payload_json FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if found is None:
                return None
            previous_state = _canonical_state(found["status"]) or "New"
            if target_state not in INCIDENT_TRANSITIONS.get(previous_state, ()):
                raise ValueError(f"transition from {previous_state} to {target_state} is not allowed")
            payload = json.loads(found["payload_json"])
            lifecycle_event = {
                "created_at": now,
                "event_type": "incident.validated",
                "previous_state": previous_state,
                "state": target_state,
                "note": note,
                "action_taken": action_taken,
            }
            payload.setdefault("lifecycle_history", []).append(lifecycle_event)
            conn.execute("UPDATE incidents SET status=?,updated_at=?,payload_json=? WHERE id=?",
                         (target_state, now, json.dumps(payload, ensure_ascii=False, default=str), incident_id))
            conn.execute("INSERT INTO validation_events(incident_id,created_at,state,note,action_taken) VALUES(?,?,?,?,?)",
                         (incident_id, now, target_state, note, action_taken))
            conn.execute("INSERT INTO system_events(created_at,event_type,incident_id,payload_json) VALUES(?,?,?,?)",
                         (now, "incident.validated", incident_id,
                          json.dumps({"previous_state": previous_state, "state": target_state,
                                      "note": note, "action_taken": action_taken})))
        return self.get_incident(incident_id)

    def approve_response(self, incident_id: str, approved_by: str = "analyst") -> dict | None:
        now = _now()
        with self._connect() as conn:
            row = conn.execute("SELECT status,payload_json FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            current_state = _canonical_state(row["status"]) or "New"
            if current_state not in {"Triaged", "Contained"}:
                raise ValueError("Response approval requires a triaged or contained incident")
            payload = json.loads(row["payload_json"])
            workflow = payload.setdefault("response_workflow", {})
            if workflow.get("state") == "monitoring":
                raise ValueError("Benign incidents have no response actions to approve")
            for task in workflow.get("tasks", []):
                if task.get("status") == "proposed":
                    task["status"] = "approved_for_simulation"
                    task["approved_by"] = approved_by
            workflow["state"] = "approved_for_simulation"
            workflow["approved_at"] = now
            workflow["approved_by"] = approved_by

            playbook = payload.get("playbook") or {}
            simulation_steps = []
            for phase in playbook.get("phases", []):
                for step in phase.get("steps", []):
                    simulation_steps.append({
                        "phase": phase.get("name", "unknown"),
                        "action": step.get("action", ""),
                        "technique_id": step.get("technique_id"),
                        "evidence_ids": step.get("evidence_ids", []),
                        "status": "WOULD_RUN",
                    })
            if not simulation_steps:
                for task in workflow.get("tasks", []):
                    simulation_steps.append({
                        "phase": "response",
                        "action": task.get("description", ""),
                        "technique_id": None,
                        "evidence_ids": [],
                        "status": "WOULD_RUN",
                    })
            simulation_log = {
                "log_id": str(uuid.uuid4()),
                "label": "SIMULATION",
                "mode": "dry-run",
                "executed": False,
                "created_at": now,
                "approved_by": approved_by,
                "steps": simulation_steps,
            }
            workflow.setdefault("simulation_logs", []).append(simulation_log)
            lifecycle_history = payload.setdefault("lifecycle_history", [])
            lifecycle_history.extend([
                {"created_at": now, "event_type": "response.approved", "approved_by": approved_by},
                {"created_at": now, "event_type": "response.simulation_logged",
                 "label": "SIMULATION", "mode": "dry-run", "executed": False,
                 "log_id": simulation_log["log_id"], "steps_count": len(simulation_steps),
                 "approved_by": approved_by},
            ])
            conn.execute("UPDATE incidents SET updated_at=?,payload_json=? WHERE id=?",
                         (now, json.dumps(payload, ensure_ascii=False, default=str), incident_id))
            conn.execute("INSERT INTO system_events(created_at,event_type,incident_id,payload_json) VALUES(?,?,?,?)",
                         (now, "response.approved", incident_id,
                          json.dumps({"approved_by": approved_by})))
            conn.execute("INSERT INTO system_events(created_at,event_type,incident_id,payload_json) VALUES(?,?,?,?)",
                         (now, "response.simulation_logged", incident_id,
                          json.dumps({"label": "SIMULATION", "mode": "dry-run", "executed": False,
                                      "log_id": simulation_log["log_id"], "steps_count": len(simulation_steps),
                                      "approved_by": approved_by})))
        return self.get_incident(incident_id)

    def record_event(self, event_type: str, payload: dict, incident_id: str | None = None) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO system_events(created_at,event_type,incident_id,payload_json) VALUES(?,?,?,?)",
                (_now(), event_type, incident_id, json.dumps(payload, ensure_ascii=False, default=str)),
            )
            return int(cursor.lastrowid)

    def audit_trail(self, limit: int = 100) -> list[dict]:
        """Read-only view of analyst approvals and validations, newest first."""
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,created_at,event_type,incident_id,payload_json "
                "FROM system_events "
                "WHERE event_type IN ('response.approved','response.simulation_logged','incident.validated') "
                "ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        trail = []
        for row in rows:
            item = dict(row)
            raw = item.pop("payload_json", "{}")
            try:
                item["details"] = json.loads(raw)
            except (TypeError, ValueError):
                item["details"] = {"raw": raw}
            trail.append(item)
        return trail

    def documents(self) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM evidence_documents ORDER BY family,title")]

    def events_since(self, event_id: int = 0, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM system_events WHERE id>? ORDER BY id LIMIT ?", (event_id, limit)
            )]

    def latest_event_id(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) AS latest_id FROM system_events").fetchone()
        return int(row["latest_id"])

    def list_iocs(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM threat_iocs ORDER BY created_at DESC LIMIT ?", (limit,)
            )]


evidence_store = EvidenceStore()
