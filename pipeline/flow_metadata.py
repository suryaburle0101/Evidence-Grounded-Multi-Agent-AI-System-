"""Metadata helpers for flow rows; metadata is preserved but never fed to ML models."""
from __future__ import annotations

import re
from collections.abc import Mapping


FIELD_ALIASES = {
    "source_ip": ("source ip", "src ip", "source_ip", "src_ip", "srcip", "source address", "sourceip"),
    "destination_ip": ("destination ip", "dest ip", "dst ip", "destination_ip", "dest_ip", "dst_ip", "dstip", "destination address"),
    "source_host": ("source host", "src host", "source hostname", "src hostname", "source_host", "src_host", "source_hostname"),
    "destination_host": ("destination host", "dest host", "dst host", "hostname", "destination_host", "dst_host", "destination_hostname"),
    "source_port": ("source port", "src port", "source_port", "src_port", "sport"),
    "destination_port": ("destination port", "dest port", "dst port", "destination_port", "dest_port", "dsport"),
    "protocol": ("transport protocol", "proto", "protocol"),
    "timestamp": ("timestamp", "time", "ts", "start time", "flow start", "flow start time", "stime"),
    "end_timestamp": ("end time", "flow end", "flow end time", "end_timestamp", "ltime"),
    "flow_id": ("flow id", "flow_id", "uid", "id"),
    "sensor": ("sensor", "sensor id", "sensor_id", "capture source"),
}


def normalize_name(value: object) -> str:
    return " ".join(re.sub(r"[_-]+", " ", str(value).strip().casefold()).split())


def resolve_metadata_columns(columns) -> dict[str, str]:
    normalized = {normalize_name(column): str(column) for column in columns}
    resolved = {}
    for canonical, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            source = normalized.get(normalize_name(alias))
            if source is not None:
                resolved[canonical] = source
                break
    return resolved


def _safe_value(value):
    if value is None:
        return None
    try:
        if value != value:  # NaN / NaT
            return None
    except (TypeError, ValueError):
        pass
    if hasattr(value, "item"):
        try:
            value = value.item()
        except (ValueError, TypeError):
            pass
    if isinstance(value, str):
        value = value.strip()
        return value[:255] if value else None
    if isinstance(value, (int, float, bool)):
        return value
    return str(value)[:255]


def extract_flow_context(flow) -> dict:
    if hasattr(flow, "to_dict") and not isinstance(flow, Mapping):
        flow = flow.to_dict()
    if not isinstance(flow, Mapping):
        return {}
    columns = resolve_metadata_columns(flow.keys())
    result = {}
    for canonical, source in columns.items():
        value = _safe_value(flow.get(source))
        if value is not None:
            result[canonical] = value
    return result
