import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "score_findings.py"
SPEC = importlib.util.spec_from_file_location("score_findings", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ScoreFindingsTests(unittest.TestCase):
    def test_no_findings_is_ready(self):
        result = MODULE.score([])
        self.assertEqual(result["score"], 100.0)
        self.assertEqual(result["decision"], "READY")
        self.assertEqual(result["blockers"], [])

    def test_confirmed_medium_deducts_full_amount(self):
        result = MODULE.score(
            [
                {
                    "id": "DB-002",
                    "category": "Database & Data Integrity",
                    "severity": "Medium",
                    "confidence": "CONFIRMED",
                }
            ]
        )
        self.assertEqual(result["score"], 97.0)
        self.assertEqual(result["category_scores"]["Database & Data Integrity"], 12.0)

    def test_likely_high_gets_half_deduction(self):
        result = MODULE.score(
            [
                {
                    "id": "SEC-007",
                    "category": "Security",
                    "severity": "High",
                    "confidence": "LIKELY",
                }
            ]
        )
        self.assertEqual(result["score"], 96.25)
        self.assertEqual(result["category_scores"]["Security"], 26.25)
        self.assertEqual(result["decision"], "READY")

    def test_not_verified_does_not_deduct(self):
        result = MODULE.score(
            [
                {
                    "id": "OBS-001",
                    "category": "Observability",
                    "severity": "Medium",
                    "confidence": "NOT VERIFIED",
                }
            ]
        )
        self.assertEqual(result["score"], 100.0)
        self.assertEqual(result["verification_gaps"], ["OBS-001"])

    def test_confirmed_critical_zeroes_category_and_blocks(self):
        result = MODULE.score(
            [
                {
                    "id": "SEC-004",
                    "category": "Security",
                    "severity": "Critical",
                    "confidence": "CONFIRMED",
                }
            ]
        )
        self.assertEqual(result["category_scores"]["Security"], 0.0)
        self.assertEqual(result["score"], 70.0)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertEqual(result["blockers"], ["SEC-004"])

    def test_explicit_confirmed_blocker_overrides_high_score(self):
        result = MODULE.score(
            [
                {
                    "id": "REL-X",
                    "category": "Reliability",
                    "severity": "Low",
                    "confidence": "CONFIRMED",
                    "blocker": True,
                }
            ]
        )
        self.assertEqual(result["score"], 99.0)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertEqual(result["blockers"], ["REL-X"])

    def test_invalid_category_is_rejected(self):
        with self.assertRaises(MODULE.ScoringError):
            MODULE.score(
                [
                    {
                        "id": "BAD-001",
                        "category": "Unknown",
                        "severity": "Low",
                        "confidence": "CONFIRMED",
                    }
                ]
            )


if __name__ == "__main__":
    unittest.main()
