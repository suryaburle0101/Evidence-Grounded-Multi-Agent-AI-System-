"""Typed payload contracts for the orchestrated analysis agents."""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict


FlowRecord = dict[str, Any]


class AgentTraceEntry(TypedDict):
    agent: str
    role: str
    status: Literal["complete", "unavailable"]
    duration_ms: int
    input_summary: str
    output_summary: str


class EvidenceTrailItem(TypedDict):
    id: str
    type: Literal["model", "decision", "investigation", "rare_family", "flow_evidence", "threat_intel", "reference_doc"]
    source: str
    value: Any
    direction: Literal["supports ATTACK", "supports BENIGN", "neutral"]
    weight: float | None


class PlaybookStep(TypedDict):
    action: str
    technique_id: str | None
    technique_name: str | None
    evidence_ids: list[str]


class PlaybookPhase(TypedDict):
    name: Literal["contain", "eradicate", "recover", "verify"]
    steps: list[PlaybookStep]
    status: Literal["ready", "no_supporting_evidence"]


class IncidentPlaybook(TypedDict, total=False):
    family: str
    playbook_label: str
    generic_playbook: bool
    technique_id: str | None
    technique_name: str | None
    knowledge_base_source: str
    knowledge_base_reference: str
    knowledge_base_note: str
    phases: list[PlaybookPhase]
    execution_notice: str


class ModelPrediction(TypedDict, total=False):
    model: str
    attack_family: str
    binary_prediction: int
    binary_attack_probability: float
    binary_benign_probability: float
    confidence: float


class DetectionInput(TypedDict):
    flow: FlowRecord


class DetectionOutput(TypedDict, total=False):
    agent: str
    detection_state: str
    model_agreement: bool
    predicted_attack: str | None
    combined_confidence: float | None
    random_forest: ModelPrediction
    xgboost: ModelPrediction
    requires_investigation: bool


class RareFamilyInput(TypedDict):
    flow: FlowRecord


class RareFamilyOutput(TypedDict, total=False):
    agent: str
    available: bool
    any_triggered: bool
    top_family: str | None
    top_probability: float | None
    scores: dict[str, float]
    thresholds: dict[str, float]
    triggered: dict[str, bool]
    error: str


class InvestigationInput(TypedDict):
    detection: DetectionOutput


class InvestigationOutput(TypedDict, total=False):
    agent: str
    finding: str
    severity: str
    investigation_required: bool
    investigation_priority: str
    random_forest_attack_probability: float
    xgboost_attack_probability: float
    average_attack_probability: float
    probability_difference: float
    suspected_attack: str | None
    explanation: str
    conclusion: str


class EvidenceInput(TypedDict):
    investigation: InvestigationOutput
    flow: FlowRecord
    rare_family: NotRequired[RareFamilyOutput]


class EvidenceOutput(TypedDict, total=False):
    agent: str
    evidence_state: str
    evidence_found: bool
    attack: str | None
    technique_id: str | None
    technique_name: str | None
    source_name: str | None
    flow_evidence_score: float | None
    flow_evidence_level: str | None
    flow_evidence_triggered: bool
    message: str


class ThreatIntelInput(TypedDict):
    flow: FlowRecord


class ThreatIntelOutput(TypedDict, total=False):
    available: bool
    matched: bool
    match_count: int
    max_confidence: float
    family: str | None
    matches: list[dict[str, Any]]
    error: str


class DecisionInput(TypedDict):
    detection: DetectionOutput
    investigation: InvestigationOutput
    evidence: EvidenceOutput
    rare_family: RareFamilyOutput
    threat_intel: ThreatIntelOutput


class DecisionOutput(TypedDict, total=False):
    agent: str
    final_decision: Literal["BENIGN", "REVIEW", "ATTACK"]
    final_attack: str
    decision_confidence: float
    correlation_score: float
    correlation_reasons: list[str]
    evidence_trail: list[EvidenceTrailItem]
    explanation: str


class RiskInput(TypedDict):
    decision: DecisionOutput
    investigation: InvestigationOutput
    threat_intel: ThreatIntelOutput
    asset_context: NotRequired[dict[str, Any] | None]


class RiskOutput(TypedDict, total=False):
    score: float
    level: str
    severity: str
    likelihood: float
    impact: float
    factors: dict[str, Any]
    handling: str


class ResponseInput(TypedDict):
    investigation: InvestigationOutput
    evidence: EvidenceOutput
    decision: NotRequired[DecisionOutput | None]
    risk: NotRequired[RiskOutput | None]


class ResponseOutput(TypedDict, total=False):
    agent: str
    response_state: str
    requires_action: bool
    severity: str
    attack: str
    recommended_actions: list[str]
    message: str


class LocalRagInput(TypedDict):
    attack: str
    decision: str
    evidence: EvidenceOutput
    flow: NotRequired[FlowRecord]
    generate: NotRequired[bool]
    evidence_trail: NotRequired[list[EvidenceTrailItem]]
    response: NotRequired[ResponseOutput]


class LocalRagOutput(TypedDict, total=False):
    status: str
    answer: str | None
    query: str
    sources: list[dict[str, Any]]
    analyst_note: str | None
    note_validation: str
    note_validation_reason: str | None


class AnalysisResult(TypedDict, total=False):
    pipeline_version: str
    git_commit_hash: str
    pipeline_completed: bool
    detection: DetectionOutput
    rare_family: RareFamilyOutput
    investigation: InvestigationOutput
    evidence: EvidenceOutput
    threat_intel: ThreatIntelOutput
    decision: DecisionOutput
    risk: RiskOutput
    response: ResponseOutput
    rag: LocalRagOutput
    evidence_trail: list[EvidenceTrailItem]
    agent_trace: list[AgentTraceEntry]
    playbook: IncidentPlaybook
