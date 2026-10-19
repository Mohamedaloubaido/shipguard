#!/usr/bin/env python3
"""Deterministically score ShipGuard findings.

Input is a JSON object with a `findings` array, or a raw findings array.
Each finding should include:

- id: stable finding ID
- category: one of the ShipGuard scoring categories
- severity: Critical, High, Medium, Low, or Info
- confidence: CONFIRMED, LIKELY, or NOT VERIFIED
- blocker: optional boolean for an explicitly verified automatic blocker

The scorer performs arithmetic and launch-decision logic only. It does not
infer whether a finding is true.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

CATEGORY_WEIGHTS = {
    "Security": 30.0,
    "Reliability": 20.0,
    "Database & Data Integrity": 15.0,
    "Deployment & Configuration": 15.0,
    "Observability": 10.0,
    "Performance": 10.0,
}

DEFAULT_DEDUCTIONS = {
    "High": 7.5,
    "Medium": 3.0,
    "Low": 1.0,
    "Info": 0.0,
}

CONFIDENCE_MULTIPLIERS = {
    "CONFIRMED": 1.0,
    "LIKELY": 0.5,
    "NOT VERIFIED": 0.0,
}

SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


class ScoringError(ValueError):
    pass


def load_findings(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScoringError(f"input file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ScoringError(f"invalid JSON: {exc}") from exc

    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict) and isinstance(data.get("findings"), list):
        findings = data["findings"]
    else:
        raise ScoringError("input must be a findings array or an object containing a findings array")

    if not all(isinstance(item, dict) for item in findings):
        raise ScoringError("every finding must be a JSON object")

    return findings


def validate_finding(finding: dict[str, Any], index: int) -> None:
    prefix = f"finding[{index}]"
    for field in ("id", "category", "severity", "confidence"):
        if not isinstance(finding.get(field), str) or not finding[field].strip():
            raise ScoringError(f"{prefix}.{field} must be a non-empty string")

    if finding["category"] not in CATEGORY_WEIGHTS:
        allowed = ", ".join(CATEGORY_WEIGHTS)
        raise ScoringError(f"{prefix}.category must be one of: {allowed}")

    if finding["severity"] not in SEVERITIES:
        allowed = ", ".join(sorted(SEVERITIES))
        raise ScoringError(f"{prefix}.severity must be one of: {allowed}")

    if finding["confidence"] not in CONFIDENCE_MULTIPLIERS:
        allowed = ", ".join(CONFIDENCE_MULTIPLIERS)
        raise ScoringError(f"{prefix}.confidence must be one of: {allowed}")

    if "blocker" in finding and not isinstance(finding["blocker"], bool):
        raise ScoringError(f"{prefix}.blocker must be boolean when provided")

    if "deduction" in finding:
        deduction = finding["deduction"]
        if not isinstance(deduction, (int, float)) or isinstance(deduction, bool) or deduction < 0:
            raise ScoringError(f"{prefix}.deduction must be a non-negative number")


def base_deduction(finding: dict[str, Any]) -> float:
    category = finding["category"]
    severity = finding["severity"]

    if "deduction" in finding:
        return float(finding["deduction"])

    if severity == "Critical":
        return CATEGORY_WEIGHTS[category]

    return DEFAULT_DEDUCTIONS[severity]


def score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    category_scores = dict(CATEGORY_WEIGHTS)
    applied: list[dict[str, Any]] = []
    blockers: list[str] = []
    verification_gaps: list[str] = []

    for index, finding in enumerate(findings):
        validate_finding(finding, index)

        finding_id = finding["id"]
        category = finding["category"]
        severity = finding["severity"]
        confidence = finding["confidence"]
        multiplier = CONFIDENCE_MULTIPLIERS[confidence]

        deduction = min(base_deduction(finding) * multiplier, category_scores[category])
        category_scores[category] = max(0.0, category_scores[category] - deduction)

        if confidence == "NOT VERIFIED":
            verification_gaps.append(finding_id)

        automatic_critical_blocker = severity == "Critical" and confidence == "CONFIRMED"
        explicit_blocker = bool(finding.get("blocker", False)) and confidence == "CONFIRMED"
        is_blocker = automatic_critical_blocker or explicit_blocker

        if is_blocker:
            blockers.append(finding_id)

        applied.append(
            {
                "id": finding_id,
                "category": category,
                "severity": severity,
                "confidence": confidence,
                "base_deduction": round(base_deduction(finding), 2),
                "applied_deduction": round(deduction, 2),
                "blocker": is_blocker,
            }
        )

    total = round(sum(category_scores.values()), 2)

    if blockers or total < 75:
        decision = "BLOCKED"
    elif total < 90:
        decision = "NEEDS WORK"
    else:
        decision = "READY"

    return {
        "score": total,
        "decision": decision,
        "category_scores": {key: round(value, 2) for key, value in category_scores.items()},
        "blockers": blockers,
        "verification_gaps": verification_gaps,
        "applied_findings": applied,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score ShipGuard findings deterministically.")
    parser.add_argument("input", help="Path to findings JSON")
    parser.add_argument("--output", "-o", help="Optional output JSON path")
    args = parser.parse_args()

    try:
        findings = load_findings(Path(args.input))
        result = score(findings)
    except ScoringError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        print(f"ShipGuard score written to {output}")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
