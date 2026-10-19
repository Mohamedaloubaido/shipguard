import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze_next_supabase.py"


class NextSupabaseAnalyzerTests(unittest.TestCase):
    def run_analyzer(self, repo: Path) -> dict:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(repo)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return json.loads(result.stdout)

    def write_package(self, repo: Path) -> None:
        (repo / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {
                        "next": "16.0.0",
                        "react": "19.0.0",
                        "@supabase/supabase-js": "2.0.0",
                    }
                }
            ),
            encoding="utf-8",
        )

    def test_detects_supported_stack(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.write_package(repo)

            report = self.run_analyzer(repo)

            self.assertTrue(report["supported_stack"]["nextjs_detected"])
            self.assertTrue(report["supported_stack"]["supabase_detected"])
            self.assertTrue(report["supported_stack"]["fully_matched"])

    def test_next_public_service_role_is_confirmed_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.write_package(repo)
            (repo / "lib").mkdir()
            (repo / "lib" / "supabase.ts").write_text(
                "const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n",
                encoding="utf-8",
            )

            report = self.run_analyzer(repo)
            matches = [f for f in report["findings"] if f["id"] == "NS-SEC-001"]

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["severity"], "Critical")
            self.assertEqual(matches[0]["confidence"], "CONFIRMED")
            self.assertTrue(matches[0]["blocker"])

    def test_client_component_service_role_is_confirmed_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.write_package(repo)
            (repo / "app").mkdir()
            (repo / "app" / "client.tsx").write_text(
                "'use client';\nconst key = process.env.SUPABASE_SERVICE_ROLE_KEY;\nexport default function X(){return null}\n",
                encoding="utf-8",
            )

            report = self.run_analyzer(repo)
            matches = [f for f in report["findings"] if f["id"] == "NS-SEC-002"]

            self.assertEqual(len(matches), 1)
            self.assertTrue(matches[0]["blocker"])

    def test_missing_rls_in_migrations_is_likely_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.write_package(repo)
            migration = repo / "supabase" / "migrations"
            migration.mkdir(parents=True)
            (migration / "001.sql").write_text(
                "create table public.messages(id bigint primary key);\n",
                encoding="utf-8",
            )

            report = self.run_analyzer(repo)
            matches = [f for f in report["findings"] if f["id"] == "NS-DB-001"]

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["severity"], "High")
            self.assertEqual(matches[0]["confidence"], "LIKELY")

    def test_rls_enablement_avoids_missing_rls_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.write_package(repo)
            migration = repo / "supabase" / "migrations"
            migration.mkdir(parents=True)
            (migration / "001.sql").write_text(
                "create table public.messages(id bigint primary key);\n"
                "alter table public.messages enable row level security;\n",
                encoding="utf-8",
            )

            report = self.run_analyzer(repo)
            matches = [f for f in report["findings"] if f["id"] == "NS-DB-001"]

            self.assertEqual(matches, [])

    def test_mutating_route_without_local_auth_is_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.write_package(repo)
            route = repo / "app" / "api" / "items"
            route.mkdir(parents=True)
            (route / "route.ts").write_text(
                "export async function POST(request: Request) { return Response.json({ok:true}) }\n",
                encoding="utf-8",
            )

            report = self.run_analyzer(repo)
            matches = [f for f in report["findings"] if f["id"] == "NS-AUTH-001"]

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["confidence"], "NOT VERIFIED")
            self.assertFalse(matches[0]["blocker"])

    def test_dangerous_html_requires_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.write_package(repo)
            (repo / "app").mkdir()
            (repo / "app" / "page.tsx").write_text(
                "export default function Page(){return <div dangerouslySetInnerHTML={{__html: html}} />}\n",
                encoding="utf-8",
            )

            report = self.run_analyzer(repo)
            matches = [f for f in report["findings"] if f["id"] == "NS-SEC-003"]

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["confidence"], "LIKELY")


if __name__ == "__main__":
    unittest.main()
