#!/usr/bin/env python3
"""ShipGuard analyzer for Next.js + Supabase repositories.

The analyzer performs conservative static checks. It distinguishes confirmed
repository evidence from likely risks and verification gaps. It never connects
to a live Supabase project and never emits secret values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

SKIP_DIRS = {
    ".git", ".next", "node_modules", "dist", "build", "coverage", ".turbo", ".cache", "vendor"
}
SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SQL_SUFFIXES = {".sql"}

NEXT_PUBLIC_SERVICE_ROLE_RE = re.compile(
    r"(?i)NEXT_PUBLIC_[A-Z0-9_]*(?:SUPABASE[A-Z0-9_]*)?SERVICE[_-]?ROLE[A-Z0-9_]*"
)
SERVICE_ROLE_RE = re.compile(r"(?i)(?:SUPABASE[_-]?)?SERVICE[_-]?ROLE(?:[_-]?KEY)?")
USE_CLIENT_RE = re.compile(r"(?m)^\s*['\"]use client['\"]\s*;?")
DANGEROUS_HTML_RE = re.compile(r"\bdangerouslySetInnerHTML\b")
MUTATION_EXPORT_RE = re.compile(r"(?m)\bexport\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|\bexport\s+const\s+(POST|PUT|PATCH|DELETE)\b")
AUTH_EVIDENCE_RE = re.compile(
    r"(?i)(auth\.getUser\s*\(|getUser\s*\(|getSession\s*\(|currentUser\s*\(|requireAuth\s*\(|verifyToken\s*\(|supabase\.auth\.|auth\s*\(\s*\))"
)
CREATE_TABLE_RE = re.compile(
    r"(?is)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?[\"`]?([a-zA-Z_][a-zA-Z0-9_]*)[\"`]?"
)
ENABLE_RLS_RE = re.compile(
    r"(?is)\balter\s+table\s+(?:only\s+)?(?:public\.)?[\"`]?([a-zA-Z_][a-zA-Z0-9_]*)[\"`]?\s+enable\s+row\s+level\s+security\b"
)
CREATE_POLICY_RE = re.compile(
    r"(?is)\bcreate\s+policy\s+.+?\s+on\s+(?:public\.)?[\"`]?([a-zA-Z_][a-zA-Z0-9_]*)[\"`]?"
)


def run_git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return result.returncode, result.stdout.strip()
    except FileNotFoundError:
        return 127, ""


def tracked_files(repo: Path) -> list[Path]:
    code, output = run_git(repo, "ls-files")
    if code == 0:
        return [repo / line for line in output.splitlines() if line.strip()]

    files: list[Path] = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        base = Path(root)
        files.extend(base / name for name in names)
    return files


def read_text(path: Path, max_bytes: int = 1_000_000) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def relative(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_package(repo: Path) -> dict:
    path = repo / "package.json"
    text = read_text(path) if path.exists() else None
    if not text:
        return {}
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        return {}


def dependency_names(package: dict) -> set[str]:
    names: set[str] = set()
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        value = package.get(field, {})
        if isinstance(value, dict):
            names.update(value.keys())
    return names


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def finding(
    check_id: str,
    title: str,
    severity: str,
    confidence: str,
    category: str,
    blocker: bool,
    file: str | None,
    line: int | None,
    evidence: str,
    remediation: str,
) -> dict:
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "blocker": blocker,
        "file": file,
        "line": line,
        "evidence": evidence,
        "remediation": remediation,
    }


def source_findings(repo: Path, files: Iterable[Path]) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    route_count = 0
    mutating_route_count = 0
    client_component_count = 0

    for path in files:
        if path.suffix.lower() not in SOURCE_SUFFIXES or not path.is_file():
            continue
        text = read_text(path, max_bytes=500_000)
        if text is None:
            continue
        rel = relative(repo, path)
        is_client = bool(USE_CLIENT_RE.search(text))
        if is_client:
            client_component_count += 1

        public_match = NEXT_PUBLIC_SERVICE_ROLE_RE.search(text)
        if public_match:
            findings.append(
                finding(
                    "NS-SEC-001",
                    "Privileged Supabase service-role credential uses a NEXT_PUBLIC name",
                    "Critical",
                    "CONFIRMED",
                    "Security",
                    True,
                    rel,
                    line_number(text, public_match.start()),
                    "Source code references a NEXT_PUBLIC variable whose name indicates a Supabase service-role credential. NEXT_PUBLIC variables are intended for client exposure in Next.js builds.",
                    "Remove the privileged credential from all NEXT_PUBLIC variables, rotate the exposed credential, and keep service-role access in server-only code.",
                )
            )

        if is_client:
            service_match = SERVICE_ROLE_RE.search(text)
            if service_match:
                findings.append(
                    finding(
                        "NS-SEC-002",
                        "Supabase service-role credential referenced by a Client Component",
                        "Critical",
                        "CONFIRMED",
                        "Security",
                        True,
                        rel,
                        line_number(text, service_match.start()),
                        "A file marked 'use client' references a service-role credential identifier.",
                        "Move privileged Supabase operations to a server-only module or Route Handler, rotate any exposed credential, and expose only least-privilege operations to the client.",
                    )
                )

        html_match = DANGEROUS_HTML_RE.search(text)
        if html_match:
            findings.append(
                finding(
                    "NS-SEC-003",
                    "Raw HTML rendering requires sanitization verification",
                    "Medium",
                    "LIKELY",
                    "Security",
                    False,
                    rel,
                    line_number(text, html_match.start()),
                    "dangerouslySetInnerHTML is used in application source.",
                    "Verify that all rendered HTML is trusted or sanitized with an appropriate allowlist-based sanitizer before rendering.",
                )
            )

        normalized = rel.lower()
        is_route = bool(re.search(r"(^|/)app/api/.+/route\.(?:js|jsx|ts|tsx)$", normalized))
        if is_route:
            route_count += 1
            mutation = MUTATION_EXPORT_RE.search(text)
            if mutation:
                mutating_route_count += 1
                if not AUTH_EVIDENCE_RE.search(text):
                    findings.append(
                        finding(
                            "NS-AUTH-001",
                            "Authentication not verified for a mutating Route Handler",
                            "Medium",
                            "NOT VERIFIED",
                            "Security",
                            False,
                            rel,
                            line_number(text, mutation.start()),
                            "The Route Handler exports a mutating HTTP method, but ShipGuard did not find a recognized authentication check in the same file.",
                            "Verify whether this route is intentionally public. Otherwise enforce authentication and authorization server-side. If authentication is centralized elsewhere, document or configure that evidence for the audit.",
                        )
                    )

    return findings, {
        "route_handlers": route_count,
        "mutating_route_handlers": mutating_route_count,
        "client_components": client_component_count,
    }


def migration_findings(repo: Path, files: Iterable[Path]) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    sql_docs: list[tuple[Path, str]] = []
    for path in files:
        if path.suffix.lower() not in SQL_SUFFIXES or not path.is_file():
            continue
        rel = relative(repo, path).lower()
        if "supabase/" not in rel and "migration" not in rel:
            continue
        text = read_text(path, max_bytes=2_000_000)
        if text is not None:
            sql_docs.append((path, text))

    created: dict[str, tuple[str, int]] = {}
    rls_enabled: set[str] = set()
    policies: Counter[str] = Counter()

    for path, text in sql_docs:
        rel = relative(repo, path)
        for match in CREATE_TABLE_RE.finditer(text):
            table = match.group(1).lower()
            created.setdefault(table, (rel, line_number(text, match.start())))
        for match in ENABLE_RLS_RE.finditer(text):
            rls_enabled.add(match.group(1).lower())
        for match in CREATE_POLICY_RE.finditer(text):
            policies[match.group(1).lower()] += 1

    for table, (rel, line) in sorted(created.items()):
        if table not in rls_enabled:
            findings.append(
                finding(
                    "NS-DB-001",
                    f"RLS enablement not found for Supabase table '{table}'",
                    "High",
                    "LIKELY",
                    "Database & Data Integrity",
                    False,
                    rel,
                    line,
                    f"Repository migrations create table '{table}', but no ALTER TABLE statement enabling row-level security for that table was found in the scanned migrations.",
                    "Enable RLS for exposed application tables and add explicit least-privilege policies. Confirm the live database state before treating this as a production defect.",
                )
            )

    return findings, {
        "sql_files_scanned": len(sql_docs),
        "tables_created": sorted(created),
        "tables_with_rls_enablement": sorted(rls_enabled),
        "policy_counts": dict(sorted(policies.items())),
    }


def summarize(findings: list[dict]) -> dict:
    severity = Counter(item["severity"] for item in findings)
    confidence = Counter(item["confidence"] for item in findings)
    return {
        "finding_count": len(findings),
        "blocker_count": sum(1 for item in findings if item["blocker"]),
        "by_severity": dict(sorted(severity.items())),
        "by_confidence": dict(sorted(confidence.items())),
    }


def analyze(repo: Path) -> dict:
    files = tracked_files(repo)
    package = load_package(repo)
    deps = dependency_names(package)
    nextjs = "next" in deps
    supabase = any(dep.startswith("@supabase/") or dep == "supabase" for dep in deps) or (repo / "supabase").exists()

    source_results, source_evidence = source_findings(repo, files)
    migration_results, migration_evidence = migration_findings(repo, files)
    findings = source_results + migration_results

    return {
        "shipguard_analyzer": "nextjs-supabase",
        "analyzer_version": 1,
        "repository": str(repo),
        "supported_stack": {
            "nextjs_detected": nextjs,
            "supabase_detected": supabase,
            "fully_matched": nextjs and supabase,
        },
        "summary": summarize(findings),
        "findings": findings,
        "evidence": {
            "source": source_evidence,
            "supabase_migrations": migration_evidence,
        },
        "limitations": [
            "Static analysis cannot prove the live Supabase RLS or policy state.",
            "Authentication may be enforced in middleware, wrappers, reverse proxies, or infrastructure that this analyzer cannot infer reliably.",
            "A raw-HTML finding does not prove exploitable XSS; it requires data-flow and sanitization verification.",
            "The analyzer never emits credential values and does not attempt to validate credentials against external services.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a Next.js + Supabase repository for production-readiness risks.")
    parser.add_argument("path", nargs="?", default=".", help="Repository path (default: current directory)")
    parser.add_argument("--output", "-o", help="Write JSON report to this file")
    args = parser.parse_args()

    repo = Path(args.path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        print(f"error: repository path does not exist: {repo}", file=sys.stderr)
        return 2

    report = analyze(repo)
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        print(f"ShipGuard Next.js + Supabase report written to {output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
