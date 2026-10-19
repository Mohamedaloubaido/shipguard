#!/usr/bin/env python3
"""Collect deterministic repository evidence for a ShipGuard audit.

This helper does not make the final launch decision. It gathers facts that an
agent can use together with SKILL.md, checks/core-checks.md, and the scoring
model. Secret values are never emitted in the report.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

SKIP_DIRS = {
    ".git",
    ".next",
    ".nuxt",
    ".output",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".turbo",
    ".cache",
    "vendor",
}

TEXT_SUFFIXES = {
    ".env",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".md",
    ".sql",
    ".py",
    ".rb",
    ".go",
    ".java",
    ".kt",
    ".php",
    ".rs",
    ".sh",
    ".ps1",
}

SECRET_NAME_RE = re.compile(
    r"(?i)(secret|token|password|passwd|private[_-]?key|service[_-]?role|api[_-]?key|access[_-]?key)"
)
ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.+?)\s*$")
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:$|changeme|change-me|example|sample|placeholder|your[_-].*|<.*>|\$\{.*\}|xxx+|test|dummy)$"
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
        for name in names:
            files.append(base / name)
    return files


def relative(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def read_text(path: Path, max_bytes: int = 1_000_000) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def load_json(path: Path) -> dict:
    text = read_text(path)
    if text is None:
        return {}
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        return {}


def detect_package_manager(repo: Path) -> str | None:
    candidates = [
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
        ("bun.lockb", "bun"),
        ("bun.lock", "bun"),
    ]
    for filename, manager in candidates:
        if (repo / filename).exists():
            return manager
    return None


def dependency_names(package: dict) -> set[str]:
    names: set[str] = set()
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        value = package.get(field, {})
        if isinstance(value, dict):
            names.update(value.keys())
    return names


def detect_frameworks(deps: set[str], repo: Path) -> list[str]:
    frameworks: list[str] = []
    mapping = {
        "next": "Next.js",
        "react": "React",
        "nuxt": "Nuxt",
        "vue": "Vue",
        "@sveltejs/kit": "SvelteKit",
        "svelte": "Svelte",
        "express": "Express",
        "fastify": "Fastify",
        "@nestjs/core": "NestJS",
    }
    for dep, label in mapping.items():
        if dep in deps and label not in frameworks:
            frameworks.append(label)

    if (repo / "requirements.txt").exists() or (repo / "pyproject.toml").exists():
        pytext = "\n".join(
            filter(
                None,
                [
                    read_text(repo / "requirements.txt") if (repo / "requirements.txt").exists() else None,
                    read_text(repo / "pyproject.toml") if (repo / "pyproject.toml").exists() else None,
                ],
            )
        ).lower()
        if "django" in pytext:
            frameworks.append("Django")
        if "fastapi" in pytext:
            frameworks.append("FastAPI")
        if "flask" in pytext:
            frameworks.append("Flask")

    return frameworks


def env_like(path: Path) -> bool:
    name = path.name.lower()
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def secret_assignment_findings(repo: Path, files: Iterable[Path]) -> list[dict]:
    findings: list[dict] = []
    for path in files:
        if not path.is_file():
            continue
        if not (env_like(path) or path.suffix.lower() in TEXT_SUFFIXES):
            continue
        text = read_text(path, max_bytes=300_000)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = ASSIGNMENT_RE.match(line)
            if not match:
                continue
            key, raw_value = match.groups()
            if not SECRET_NAME_RE.search(key):
                continue
            value = raw_value.strip().strip("\"'")
            if PLACEHOLDER_RE.match(value):
                continue
            if len(value) < 8:
                continue
            findings.append(
                {
                    "check_id": "SEC-001",
                    "file": relative(repo, path),
                    "line": line_number,
                    "variable": key,
                    "value": "[REDACTED]",
                    "note": "Secret-like variable with a non-placeholder value is tracked in source control; verify whether it is a real credential.",
                }
            )
    return findings


def find_matching_files(repo: Path, files: Iterable[Path], patterns: list[str], limit: int = 25) -> list[str]:
    regexes = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    matches: list[str] = []
    for path in files:
        rel = relative(repo, path)
        if any(regex.search(rel) for regex in regexes):
            matches.append(rel)
            if len(matches) >= limit:
                break
    return sorted(set(matches))


def gitignore_env_status(repo: Path) -> dict:
    path = repo / ".gitignore"
    text = read_text(path) if path.exists() else None
    if text is None:
        return {"present": False, "ignores_env": False}
    ignores_env = any(
        line.strip() in {".env", ".env.*", "*.env"}
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    return {"present": True, "ignores_env": ignores_env}


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect repository evidence for a ShipGuard audit.")
    parser.add_argument("path", nargs="?", default=".", help="Repository path (default: current directory)")
    parser.add_argument("--output", "-o", help="Write JSON evidence to this file")
    args = parser.parse_args()

    repo = Path(args.path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        print(f"error: repository path does not exist: {repo}", file=sys.stderr)
        return 2

    files = tracked_files(repo)
    package_path = repo / "package.json"
    package = load_json(package_path) if package_path.exists() else {}
    deps = dependency_names(package)
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts", {}), dict) else {}

    database_markers = find_matching_files(
        repo,
        files,
        [r"(^|/)supabase/", r"prisma/schema\.prisma$", r"drizzle\.config", r"migrations?/"],
    )
    ci_markers = find_matching_files(repo, files, [r"^\.github/workflows/", r"gitlab-ci", r"circleci", r"jenkinsfile$"])
    deploy_markers = find_matching_files(
        repo,
        files,
        [r"vercel\.json$", r"netlify\.toml$", r"dockerfile$", r"docker-compose", r"fly\.toml$", r"render\.yaml$"],
    )

    observability_deps = sorted(
        dep
        for dep in deps
        if any(token in dep.lower() for token in ("sentry", "opentelemetry", "datadog", "newrelic", "pino", "winston"))
    )

    env_files = sorted(relative(repo, p) for p in files if env_like(p))
    secret_candidates = secret_assignment_findings(repo, files)

    git_code, head = run_git(repo, "rev-parse", "HEAD")
    _, branch = run_git(repo, "branch", "--show-current")

    evidence = {
        "shipguard_evidence_version": 1,
        "repository": {
            "path": str(repo),
            "git_detected": git_code == 0,
            "branch": branch or None,
            "commit": head if git_code == 0 else None,
            "tracked_file_count": len(files),
        },
        "stack": {
            "package_manager": detect_package_manager(repo),
            "frameworks": detect_frameworks(deps, repo),
            "typescript": (repo / "tsconfig.json").exists(),
            "package_json": package_path.exists(),
        },
        "package_scripts": {
            "build": scripts.get("build"),
            "test": scripts.get("test"),
            "lint": scripts.get("lint"),
            "typecheck": scripts.get("typecheck") or scripts.get("type-check") or scripts.get("check-types"),
        },
        "security": {
            "gitignore": gitignore_env_status(repo),
            "tracked_env_files": env_files,
            "secret_assignment_candidates": secret_candidates,
        },
        "database": {
            "markers": database_markers,
        },
        "deployment": {
            "ci_markers": ci_markers,
            "deployment_markers": deploy_markers,
        },
        "observability": {
            "dependency_markers": observability_deps,
            "status": "EVIDENCE_FOUND" if observability_deps else "NOT_VERIFIED",
        },
        "limitations": [
            "This collector performs static repository inspection only.",
            "It does not prove that a detected secret-like value is an active credential.",
            "It does not inspect cloud platform settings, runtime infrastructure, WAF/rate-limit rules, production logs, backups, or live database policy state unless those are represented in the repository.",
            "Absence of a repository marker must not be treated as proof that a production control is absent.",
        ],
    }

    rendered = json.dumps(evidence, indent=2, ensure_ascii=False)
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        print(f"ShipGuard evidence written to {output}")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
