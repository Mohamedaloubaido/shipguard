import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_evidence.py"


class CollectEvidenceTests(unittest.TestCase):
    def run_collector(self, repo: Path) -> dict:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(repo)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return json.loads(result.stdout)

    def test_detects_nextjs_and_npm(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "package.json").write_text(
                json.dumps(
                    {
                        "dependencies": {"next": "16.0.0", "react": "19.0.0"},
                        "scripts": {"build": "next build", "lint": "eslint ."},
                    }
                ),
                encoding="utf-8",
            )
            (repo / "package-lock.json").write_text("{}", encoding="utf-8")
            (repo / "tsconfig.json").write_text("{}", encoding="utf-8")

            report = self.run_collector(repo)

            self.assertEqual(report["stack"]["package_manager"], "npm")
            self.assertIn("Next.js", report["stack"]["frameworks"])
            self.assertIn("React", report["stack"]["frameworks"])
            self.assertTrue(report["stack"]["typescript"])
            self.assertEqual(report["package_scripts"]["build"], "next build")

    def test_secret_candidate_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".env.production").write_text(
                "API_SECRET=super-secret-value-123\n",
                encoding="utf-8",
            )

            report = self.run_collector(repo)
            findings = report["security"]["secret_assignment_candidates"]

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["variable"], "API_SECRET")
            self.assertEqual(findings[0]["value"], "[REDACTED]")
            self.assertNotIn("super-secret-value-123", json.dumps(report))

    def test_placeholder_secret_is_not_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".env.example").write_text(
                "API_SECRET=changeme\nSERVICE_TOKEN=${SERVICE_TOKEN}\n",
                encoding="utf-8",
            )

            report = self.run_collector(repo)

            self.assertEqual(report["security"]["secret_assignment_candidates"], [])

    def test_missing_observability_is_not_asserted_as_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "package.json").write_text("{}", encoding="utf-8")

            report = self.run_collector(repo)

            self.assertEqual(report["observability"]["status"], "NOT_VERIFIED")

    def test_detects_supabase_and_ci_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "supabase" / "migrations").mkdir(parents=True)
            (repo / "supabase" / "migrations" / "001_init.sql").write_text(
                "create table test(id bigint primary key);",
                encoding="utf-8",
            )
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / ".github" / "workflows" / "ci.yml").write_text(
                "name: ci",
                encoding="utf-8",
            )

            report = self.run_collector(repo)

            self.assertTrue(report["database"]["markers"])
            self.assertTrue(report["deployment"]["ci_markers"])


if __name__ == "__main__":
    unittest.main()
