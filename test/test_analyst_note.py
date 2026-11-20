import json
import unittest
from unittest.mock import patch

from rag.local_rag import local_rag, validate_analyst_note
from reporting.incident_report import render_markdown


EVIDENCE_TRAIL = [{
    "id": "E1",
    "type": "model",
    "source": "Random Forest",
    "value": {"attack_family": "DDoS", "binary_attack_probability": 0.9},
    "direction": "supports ATTACK",
    "weight": 0.2,
}]
RESPONSE = {"response_state": "ANALYST_REVIEW", "requires_action": True}


class AnalystNoteTests(unittest.TestCase):
    def test_valid_llm_note_is_used_and_receives_only_the_evidence_trail(self):
        note = "The DDoS signal supports ATTACK [E1]."
        with patch.object(local_rag, "retrieve", return_value=[]), \
             patch.object(local_rag, "model_status", return_value={"status": "ready", "model": "test-model"}), \
             patch.object(local_rag, "_generate_analyst_note", return_value=note) as generate:
            result = local_rag.analyze(
                "DDoS", "ATTACK", {}, generate=True,
                evidence_trail=EVIDENCE_TRAIL, response=RESPONSE,
            )

        self.assertEqual(result["analyst_note"], note)
        self.assertEqual(result["note_source"], "local_llm")
        self.assertEqual(result["note_validation"], "passed")
        generate.assert_called_once_with(EVIDENCE_TRAIL, "test-model")
        report = render_markdown({"final_decision": "ATTACK", "rag": result})
        self.assertIn("## Analyst note", report)
        self.assertIn(note, report)

    def test_invalid_llm_note_is_discarded_for_template_with_reason(self):
        invalid_note = "The DDoS signal affected 3 systems [E1]."
        with patch.object(local_rag, "retrieve", return_value=[]), \
             patch.object(local_rag, "model_status", return_value={"status": "ready", "model": "test-model"}), \
             patch.object(local_rag, "_generate_analyst_note", return_value=invalid_note):
            result = local_rag.analyze(
                "DDoS", "ATTACK", {}, generate=True,
                evidence_trail=EVIDENCE_TRAIL, response=RESPONSE,
            )

        self.assertNotEqual(result["analyst_note"], invalid_note)
        self.assertIn("Response state is ANALYST_REVIEW", result["analyst_note"])
        self.assertEqual(result["note_source"], "template_fallback")
        self.assertEqual(result["note_validation"], "failed")
        self.assertIn("number absent from the evidence", result["note_validation_reason"])
        self.assertIsNone(result["llm_draft"])

    def test_llm_off_uses_a_deterministic_template_note(self):
        with patch.object(local_rag, "retrieve", return_value=[]):
            first = local_rag.analyze(
                "DDoS", "ATTACK", {}, generate=False,
                evidence_trail=EVIDENCE_TRAIL, response=RESPONSE,
            )
            second = local_rag.analyze(
                "DDoS", "ATTACK", {}, generate=False,
                evidence_trail=EVIDENCE_TRAIL, response=RESPONSE,
            )

        self.assertEqual(first["analyst_note"], second["analyst_note"])
        self.assertEqual(first["note_source"], "template")
        self.assertEqual(first["note_validation"], "passed")
        self.assertIn("[E1]", first["analyst_note"])
        self.assertNotIn('{"', first["analyst_note"])
        self.assertNotIn("and is supports", first["analyst_note"])
        for sentence in first["analyst_note"].splitlines():
            self.assertEqual(sentence.count("[E"), 1, sentence)

    def test_template_uses_investigation_finding_and_severity_from_its_evidence_item(self):
        trail = [{
            "id": "E4", "type": "investigation", "source": "Investigation Agent",
            "value": {"finding": "ATTACK_INDICATED", "severity": "HIGH"},
            "direction": "supports ATTACK", "weight": 0.35,
        }]
        with patch.object(local_rag, "retrieve", return_value=[]):
            result = local_rag.analyze(
                "DDoS", "ATTACK", {}, generate=False,
                evidence_trail=trail, response=RESPONSE,
            )
        self.assertIn("ATTACK_INDICATED with HIGH severity [E4].", result["analyst_note"])
        self.assertEqual(result["note_validation"], "passed")

    def test_llm_prompt_contains_only_the_evidence_trail_as_factual_input(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            @staticmethod
            def read():
                return b'{"response":"The DDoS signal supports ATTACK [E1].","done_reason":"stop"}'

        def fake_urlopen(request, timeout):
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse()

        with patch("rag.local_rag.urllib.request.urlopen", side_effect=fake_urlopen):
            note = local_rag._generate_analyst_note(EVIDENCE_TRAIL, "test-model")

        prompt = captured["payload"]["prompt"]
        self.assertEqual(note, "The DDoS signal supports ATTACK [E1].")
        self.assertIn(json.dumps(EVIDENCE_TRAIL, ensure_ascii=False, sort_keys=True, separators=(",", ":")), prompt)
        self.assertNotIn("ANALYST_REVIEW", prompt)
        self.assertNotIn("recommended_actions", prompt)

    def test_validator_rejects_uncited_and_ungrounded_entities(self):
        cases = (
            ("The DDoS signal supports ATTACK.", "evidence ID"),
            ("The DDoS signal supports ATTACK [E9].", "invalid evidence ID"),
            ("The Botnet signal supports ATTACK [E1].", "attack family absent"),
            ("The DDoS signal used 203.0.113.7 [E1].", "IP address absent"),
            ("The DDoS signal affected 3 hosts [E1].", "number absent"),
        )
        for note, expected in cases:
            with self.subTest(note=note):
                reason = validate_analyst_note(
                    note, EVIDENCE_TRAIL, known_families=("DDoS", "Botnet")
                )
                self.assertIn(expected, reason)

    def test_validator_checks_citations_on_every_sentence(self):
        valid_note = (
            "The DDoS model signal supports ATTACK [E1].\n"
            "The recorded probability is 0.9 [E1]."
        )
        self.assertIsNone(validate_analyst_note(valid_note, EVIDENCE_TRAIL))

        invalid_note = (
            "The DDoS model signal supports ATTACK [E1].\n"
            "The probability deserves review."
        )
        reason = validate_analyst_note(invalid_note, EVIDENCE_TRAIL)
        self.assertIn("Sentence 2 does not end with an evidence ID", reason)


if __name__ == "__main__":
    unittest.main()
