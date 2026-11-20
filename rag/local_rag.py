"""Local TF-IDF retrieval over the evidence store, with optional Ollama answer."""

from __future__ import annotations

import json
import math
import os
import ipaddress
import re
import urllib.error
import urllib.request

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from storage.evidence_store import evidence_store


_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
_NUMBER_RE = re.compile(r"(?<![A-Za-z0-9_])[-+]?\d+(?:\.\d+)?%?(?![A-Za-z0-9_])")
_NUMBER_WORD_RE = re.compile(
    r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|"
    r"eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|"
    r"eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|"
    r"eighty|ninety|hundred|thousand|million|billion|first|second|"
    r"third|fourth|fifth|sixth|seventh|eighth|ninth|tenth)\b",
    re.IGNORECASE,
)
_CITATION_RE = re.compile(r"\[(E\d+)\]")
_CITATION_SUFFIX_RE = re.compile(r"(?:\s*\[E\d+\])+\s*[.!?]?$")
_FAMILY_CLAIM_RE = re.compile(
    r"\b(?:attack\s+family|family)\s*(?:is|:)\s*([A-Za-z][A-Za-z0-9_-]*)|"
    r"\b(?:classified|identified|predicted)\s+as\s+([A-Za-z][A-Za-z0-9_-]*)",
    re.IGNORECASE,
)


def _extract_ips(text):
    found = []
    for pattern in (_IPV4_RE, _IPV6_RE):
        for match in pattern.finditer(text):
            try:
                found.append((str(ipaddress.ip_address(match.group(0))), match.span()))
            except ValueError:
                continue
    return found


def _number_key(value):
    from decimal import Decimal, InvalidOperation

    try:
        return str(Decimal(value.rstrip("%")).normalize())
    except InvalidOperation:
        return value.casefold()


def _numbers(text):
    chars = list(_CITATION_RE.sub(lambda match: " " * len(match.group(0)), text))
    for _, (start, end) in _extract_ips(text):
        chars[start:end] = " " * (end - start)
    cleaned = "".join(chars)
    return {_number_key(match.group(0)) for match in _NUMBER_RE.finditer(cleaned)}


def _number_words(text):
    return {match.group(0).casefold() for match in _NUMBER_WORD_RE.finditer(text)}


def validate_analyst_note(note, evidence_trail, known_families=()):
    """Return a validation error or None for a fully cited, grounded note."""
    valid_ids = {
        str(item.get("id")) for item in (evidence_trail or [])
        if re.fullmatch(r"E\d+", str(item.get("id", "")))
    }
    if not valid_ids:
        return "The evidence trail has no valid IDs."
    if not isinstance(note, str) or not note.strip():
        return "The generated note is empty."

    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", note.strip()) if part.strip()]
    for index, sentence in enumerate(sentences, start=1):
        if not _CITATION_SUFFIX_RE.search(sentence):
            return f"Sentence {index} does not end with an evidence ID."
        citations = _CITATION_RE.findall(sentence)
        if not citations or any(citation not in valid_ids for citation in citations):
            invalid = next((citation for citation in citations if citation not in valid_ids), None)
            return f"Sentence {index} cites an invalid evidence ID: [{invalid}]."

    evidence_text = json.dumps(evidence_trail, ensure_ascii=False, sort_keys=True, default=str)
    for family in sorted({str(name).strip() for name in known_families if str(name).strip()}, key=len, reverse=True):
        family_pattern = re.compile(rf"(?<!\w){re.escape(family)}(?!\w)", re.IGNORECASE)
        if family_pattern.search(note) and not family_pattern.search(evidence_text):
            return f"The note mentions an attack family absent from the evidence: {family}."
    for match in _FAMILY_CLAIM_RE.finditer(note):
        family = next(group for group in match.groups() if group)
        if not re.search(rf"(?<!\w){re.escape(family)}(?!\w)", evidence_text, re.IGNORECASE):
            return f"The note mentions an attack family absent from the evidence: {family}."

    evidence_ips = {address for address, _ in _extract_ips(evidence_text)}
    for address, _ in _extract_ips(note):
        if address not in evidence_ips:
            return f"The note mentions an IP address absent from the evidence: {address}."

    evidence_numbers = _numbers(evidence_text)
    for number in _numbers(note):
        if number not in evidence_numbers:
            return f"The note mentions a number absent from the evidence: {number}."
    evidence_number_words = _number_words(evidence_text)
    for number in _number_words(note):
        if number not in evidence_number_words:
            return f"The note mentions a number absent from the evidence: {number}."
    return None


def _template_sentence(item):
    """Turn one evidence row into a short readable sentence without raw JSON."""
    value = item.get("value") if isinstance(item.get("value"), dict) else {}
    item_type = item.get("type")
    source = str(item.get("source") or "The pipeline")
    direction = str(item.get("direction") or "neutral")

    if item_type == "model":
        family = value.get("attack_family")
        probability = value.get("binary_attack_probability")
        if family and probability is not None:
            return f"{source} flagged {family} with an attack score of {probability}."
        if family:
            return f"{source} flagged the flow as {family}."
        return f"{source} produced a model signal that {direction}."
    if item_type == "decision":
        agreement = "agreed" if value.get("model_agreement") else "did not agree"
        probability = value.get("average_attack_probability")
        if probability is not None:
            return f"The decision step says the models {agreement}, with an average attack score of {probability}."
        return f"The decision step records that the models {agreement}."
    if item_type == "investigation":
        finding = value.get("finding") or "no finding recorded"
        severity = value.get("severity")
        if severity:
            return f"The investigation found {finding} with {severity} severity."
        return f"The investigation found {finding}."
    if item_type == "rare_family":
        family = value.get("top_family")
        if family:
            return f"The rare-family check flagged {family}."
        return "The rare-family check did not flag a supported family."
    if item_type == "flow_evidence":
        level = value.get("level")
        return f"Flow evidence was rated {level}." if level else f"Flow evidence {direction}."
    if item_type == "threat_intel":
        return ("Threat intelligence found a stored indicator match."
                if value.get("matched") else "Threat intelligence found no stored indicator match.")
    if item_type == "reference_doc":
        title = value.get("title") or value.get("family") or "a reference"
        source_name = value.get("source_name") or "The evidence library"
        return f"{source_name} includes a reference for {title}."
    return f"{source} signal {direction}."


def build_template_note(evidence_trail, response):
    """Create a stable note using only trail values and response state fields."""
    trail = evidence_trail or []
    if not trail:
        return None
    lines = []
    for item in trail:
        item_id = str(item.get("id", ""))
        if not re.fullmatch(r"E\d+", item_id):
            continue
        sentence = _template_sentence(item).rstrip().rstrip(".!?")
        lines.append(f"{sentence} [{item_id}].")

    response = response or {}
    state = str(response.get("response_state") or "not available")
    required = response.get("requires_action")
    required_text = "yes" if required is True else "no" if required is False else "not available"
    cited_id = next((str(item.get("id")) for item in trail if re.fullmatch(r"E\d+", str(item.get("id", "")))), None)
    if lines and cited_id:
        lines.append(f"Response state is {state}; action required is {required_text} [{cited_id}].")
    return "\n".join(lines) if lines else None


class LocalEvidenceRAG:
    def __init__(self):
        self._documents = []
        self._vectorizer = None
        self._matrix = None
        self._refresh()

    def _refresh(self):
        self._documents = evidence_store.documents()
        corpus = [f"{d['family']} {d['title']} {d['body']} {d.get('technique_id') or ''}"
                  for d in self._documents]
        if corpus:
            self._vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
            self._matrix = self._vectorizer.fit_transform(corpus)

    def retrieve(self, query: str, limit: int = 4) -> list[dict]:
        if not self._documents or not query.strip():
            return []
        vector = self._vectorizer.transform([query])
        scores = cosine_similarity(vector, self._matrix).ravel()
        indices = scores.argsort()[::-1][:max(1, min(int(limit), 10))]
        return [
            {**self._documents[i], "relevance": round(float(scores[i]), 4)}
            for i in indices if scores[i] > 0
        ]

    @staticmethod
    def model_status() -> dict:
        """Report whether the configured local model is reachable and installed."""
        model = os.environ.get("CYBER_LLM_MODEL", "").strip()
        if not model:
            return {"status": "retrieval_only", "configured": False, "model": None}
        endpoint = os.environ.get("CYBER_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        request = urllib.request.Request(endpoint + "/api/tags", method="GET")
        try:
            with urllib.request.urlopen(request, timeout=1.5) as response:
                models = json.loads(response.read().decode("utf-8")).get("models", [])
            names = {str(item.get("name", "")) for item in models}
            installed = model in names or model + ":latest" in names
            return {
                "status": "ready" if installed else "model_missing",
                "configured": True, "model": model,
                "installed": installed, "endpoint": endpoint,
            }
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            return {"status": "offline", "configured": True, "model": model,
                    "endpoint": endpoint, "error": str(exc)}

    @staticmethod
    def answer(query: str, docs: list[dict], model_context: dict | None = None,
               generate: bool = False) -> dict:
        if not docs:
            return {"status": "no_evidence", "answer": "No matching local evidence was found.", "model": None}
        model_context = model_context or {}
        metrics = model_context.get("flow_metrics", {})
        metric_text = ", ".join(f"{name}={value}" for name, value in metrics.items())
        reference_text = "; ".join(
            f"{doc.get('title')} ({doc.get('source_name') or doc.get('family')})"
            for doc in docs[:3]
        )
        answer = (
            f"Classifier result: {model_context.get('decision', 'REVIEW')} "
            f"({model_context.get('attack', 'Unknown')}). "
            + (f"Input flow features: {metric_text}. " if metric_text else "No numeric flow metrics were supplied. ")
            + f"Retrieved references: {reference_text}. "
            "References provide general context and do not prove those behaviors occurred in this flow."
        )
        return {"status": "retrieval_only", "answer": answer, "model": None}

    @staticmethod
    def _generate_analyst_note(evidence_trail, model):
        endpoint = os.environ.get("CYBER_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        prompt = (
            "Write a concise analyst note using only the evidence trail JSON below. "
            "Do not use outside knowledge, response recommendations, flow input, or retrieved documents. "
            "Do not add attack families, IP addresses, or numbers that are not present in that JSON. "
            "Write one sentence per line. Every sentence must end with one or more valid evidence IDs "
            "in square brackets, such as [E2], immediately before its final punctuation. "
            "Use no uncited headings, bullets, or prefatory text.\n\n"
            "Evidence trail JSON (the only factual input):\n"
            + json.dumps(evidence_trail, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "5m",
            "options": {"temperature": 0, "num_ctx": 2048, "num_predict": 160},
        }).encode("utf-8")
        request = urllib.request.Request(
            endpoint + "/api/generate", data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                generated = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            raise RuntimeError("The local model request failed.") from None
        if generated.get("done_reason") == "length":
            raise RuntimeError("The local model output was truncated.")
        draft = str(generated.get("response", "")).strip()
        if not draft:
            raise RuntimeError("The local model returned an empty note.")
        return draft

    def _note_result(self, evidence_trail, response, generate):
        evidence_trail = evidence_trail or []
        template_note = build_template_note(evidence_trail, response)
        template_error = validate_analyst_note(
            template_note, evidence_trail, [doc.get("family") for doc in self._documents]
        )
        model = None
        status = {"status": "retrieval_only", "configured": False}
        if generate:
            try:
                status = self.model_status()
            except Exception:
                status = {"status": "offline", "configured": True}
            model = status.get("model")

        template_fields = {
            "analyst_note": template_note,
            "llm_draft": None,
            "note_source": "template",
            "note_generation_status": "template",
            "note_validation": "passed" if template_error is None else "failed",
            "note_validation_reason": template_error,
            "model": model,
        }
        if not template_note:
            template_fields["note_validation"] = "failed"
            template_fields["note_validation_reason"] = template_error or "The evidence trail is empty."

        if not generate or status.get("status") != "ready":
            if generate and status.get("configured"):
                template_fields["note_generation_status"] = "template_fallback"
                template_fields["generation_error"] = "The local model is unavailable; a deterministic note was used."
            return template_fields

        try:
            draft = self._generate_analyst_note(evidence_trail, model)
        except RuntimeError as exc:
            template_fields["note_generation_status"] = "template_fallback"
            template_fields["generation_error"] = str(exc)
            return template_fields

        validation_error = validate_analyst_note(
            draft, evidence_trail, [doc.get("family") for doc in self._documents]
        )
        if validation_error:
            template_fields.update({
                "note_source": "template_fallback",
                "note_generation_status": "validation_fallback",
                "note_validation": "failed",
                "note_validation_reason": validation_error,
            })
            return template_fields

        return {
            "analyst_note": draft,
            "llm_draft": draft,
            "note_source": "local_llm",
            "note_generation_status": "generated",
            "note_validation": "passed",
            "note_validation_reason": None,
            "model": model,
        }

    def analyze(self, attack: str, decision: str, evidence: dict, flow=None,
                generate: bool = False, evidence_trail=None, response=None) -> dict:
        if str(decision).upper() == "BENIGN":
            result = {"status": "not_needed", "answer": None, "query": "Benign flow; retrieval skipped.", "sources": []}
            result.update(self._note_result(evidence_trail, response, generate))
            return result
        if hasattr(flow, "to_dict"):
            flow = flow.to_dict()
        metric_names = (
            "Flow Duration", "Flow Packets/s", "Flow Bytes/s",
            "Total Fwd Packets", "Total Backward Packets", "SYN Flag Count",
        )
        flow_metrics = {}
        if isinstance(flow, dict):
            for name in metric_names:
                try:
                    value = float(flow[name])
                    if math.isfinite(value):
                        flow_metrics[name] = int(value) if value.is_integer() else round(value, 3)
                except (KeyError, TypeError, ValueError, OverflowError):
                    continue
        query = " ".join(str(v) for v in (
            attack, decision, evidence.get("description", ""),
            evidence.get("technique_name", ""), evidence.get("message", ""),
        ) if v)
        docs = self.retrieve(query, limit=3)
        result = self.answer(query, docs, {
            "decision": decision, "attack": attack, "flow_metrics": flow_metrics,
        })
        result["query"] = query
        result["sources"] = [
            {key: doc.get(key) for key in ("title", "family", "source_name", "source_url", "technique_id", "relevance")}
            for doc in docs
        ]
        result.update(self._note_result(evidence_trail, response, generate))
        return result


local_rag = LocalEvidenceRAG()
