"""Local threat-intelligence feed import and flow IOC matching."""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime, timedelta, timezone

from storage.evidence_store import evidence_store


THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_SUPPORTED_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256"}


def threatfox_status() -> dict:
    """Return configuration state without revealing the credential."""
    return {"configured": bool(os.environ.get("THREATFOX_AUTH_KEY")),
            "provider": "ThreatFox (abuse.ch)"}


def sync_threatfox(days: int = 3, *, auth_key: str | None = None,
                   store=evidence_store, session=None) -> dict:
    """Fetch recent ThreatFox indicators and store supported IOC types only.

    The function never submits data to ThreatFox. The key must be provided by the
    caller or THREATFOX_AUTH_KEY; errors never fall back to an unauthenticated feed.
    """
    if not 1 <= int(days) <= 7:
        raise ValueError("days must be between 1 and 7")
    key = auth_key or os.environ.get("THREATFOX_AUTH_KEY")
    if not key:
        raise RuntimeError("ThreatFox is not configured; set THREATFOX_AUTH_KEY locally")
    body = json.dumps({"query": "get_iocs", "days": int(days)}).encode("utf-8")
    if session is not None:  # injectable transport for deterministic tests
        response = session.post(THREATFOX_API, headers={"Auth-Key": key}, json={"query": "get_iocs", "days": int(days)}, timeout=(5, 30), verify=True)
        response.raise_for_status()
        payload = response.json()
    else:
        request = urllib.request.Request(THREATFOX_API, data=body,
                                         headers={"Auth-Key": key, "Content-Type": "application/json"},
                                         method="POST")
        with urllib.request.urlopen(request, timeout=35) as response:
            content_length = int(response.headers.get("Content-Length", "0") or 0)
            if content_length > 20 * 1024 * 1024:
                raise RuntimeError("ThreatFox response exceeds the 20 MiB safety limit")
            response_body = response.read(20 * 1024 * 1024 + 1)
        if len(response_body) > 20 * 1024 * 1024:
            raise RuntimeError("ThreatFox response exceeds the 20 MiB safety limit")
        payload = json.loads(response_body.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("query_status") not in {"ok", "no_result"}:
        raise RuntimeError("ThreatFox returned an unsuccessful or invalid response")
    rows = payload.get("data") or []
    if not isinstance(rows, list):
        raise RuntimeError("ThreatFox response data must be a list")
    now = datetime.now(timezone.utc)
    entries = []
    skipped = 0
    for row in rows:
        if not isinstance(row, dict):
            skipped += 1
            continue
        kind = str(row.get("ioc_type", "")).strip().casefold()
        value = str(row.get("ioc", "")).strip()
        if kind not in THREATFOX_SUPPORTED_TYPES or not value or len(value) > 2048:
            skipped += 1
            continue
        try:
            confidence = max(0.0, min(1.0, float(row.get("confidence_level", 50)) / 100.0))
        except (TypeError, ValueError):
            confidence = 0.5
        first_seen = row.get("first_seen")
        expires_at = None
        if first_seen:
            try:
                value = str(first_seen).strip()
                try:
                    seen = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    seen = datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
                if seen.tzinfo is None:
                    seen = seen.replace(tzinfo=timezone.utc)
                expiry = seen + timedelta(days=180)
                if expiry <= now:
                    skipped += 1
                    continue
                expires_at = expiry.isoformat()
            except ValueError:
                skipped += 1
                continue
        entries.append({
            "type": "hash" if kind in {"md5", "sha1", "sha256"} else kind,
            "value": value,
            "family": row.get("malware") or row.get("threat_type"),
            "confidence": confidence,
            "severity": None,
            "source": "threatfox",
            "first_seen": first_seen,
            "expires_at": expires_at,
        })
    stored = store.add_iocs(entries, default_source="threatfox") if entries else 0
    return {"provider": "ThreatFox (abuse.ch)", "received": len(rows),
            "supported": len(entries), "skipped": skipped, "stored": stored,
            "days": int(days), "synced_at": now.isoformat()}


def load_feed(path: str | Path) -> list[dict]:
    path = Path(path)
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(payload, dict):
            payload = payload.get("indicators", payload.get("iocs", []))
        if not isinstance(payload, list):
            raise ValueError("JSON feed must contain an indicator list")
        return [dict(item) for item in payload if isinstance(item, dict)]
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        return rows
    raise ValueError("Threat-intelligence feeds must be CSV or JSON")


def _normalize_entry(entry: dict, default_source: str) -> dict | None:
    lowered = {str(key).strip().casefold(): value for key, value in entry.items()}
    value = next((lowered[k] for k in ("value", "indicator", "ioc", "ip", "domain", "url", "hash") if lowered.get(k)), None)
    if value is None:
        return None
    kind = lowered.get("type") or lowered.get("indicator_type")
    if not kind:
        text = str(value).strip()
        try:
            ipaddress.ip_address(text)
        except ValueError:
            if text.lower().startswith(("http://", "https://")):
                kind = "url"
            elif "." in text and "/" not in text and " " not in text:
                kind = "domain"
            else:
                kind = "hash"
        else:
            kind = "ip"
    confidence = lowered.get("confidence", 0.5)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.5
    return {
        "type": str(kind).strip().casefold(),
        "value": str(value).strip(),
        "family": lowered.get("family") or lowered.get("threat_type"),
        "confidence": confidence,
        "severity": lowered.get("severity"),
        "source": str(lowered.get("source") or default_source),
        "first_seen": lowered.get("first_seen") or lowered.get("date_added"),
        "expires_at": lowered.get("expires_at"),
    }


def import_feed(path: str | Path, source: str | None = None) -> dict:
    path = Path(path)
    source_name = source or path.stem
    normalized = [item for row in load_feed(path)
                  if (item := _normalize_entry(row, source_name)) is not None]
    count = evidence_store.add_iocs(normalized, default_source=source_name)
    return {"source": source_name, "received": len(normalized), "stored": count}


def analyze_flow(flow) -> dict:
    matches = evidence_store.match_iocs(flow)
    strongest = max(matches, key=lambda item: item.get("confidence", 0.0), default=None)
    return {
        "available": True,
        "matched": bool(matches),
        "match_count": len(matches),
        "max_confidence": float(strongest["confidence"]) if strongest else 0.0,
        "family": strongest.get("family") if strongest else None,
        "matches": matches,
        "source": strongest.get("source") if strongest else None,
    }
