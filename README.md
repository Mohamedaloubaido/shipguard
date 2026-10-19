# ShipGuard

**AI-powered production readiness auditor for modern web applications.**

ShipGuard is an Agent Skill that reviews a codebase before production release and produces an evidence-based readiness score, launch decision, prioritized findings, and remediation plan.

It is designed to avoid a common failure mode in AI code review: confidently reporting controls or vulnerabilities that were never actually verified. ShipGuard separates **confirmed evidence**, **likely findings**, and **verification gaps**.

## What ShipGuard evaluates

ShipGuard scores six production-readiness areas:

| Category | Weight |
| --- | ---: |
| Security | 30 |
| Reliability | 20 |
| Database & Data Integrity | 15 |
| Deployment & Configuration | 15 |
| Observability | 10 |
| Performance | 10 |
| **Total** | **100** |

The numeric score does not override a confirmed launch blocker. An application can score highly and still receive `BLOCKED` when a critical security or release failure is verified.

## Launch decisions

- `READY` — score 90-100, no confirmed blockers, and no unresolved high-severity launch risks.
- `NEEDS WORK` — score 75-89.5 and no automatic blocker.
- `BLOCKED` — score below 75, or any confirmed critical launch blocker.

Examples of automatic blockers include committed production credentials, authentication/authorization bypasses, cross-tenant data exposure, destructive release paths, and a production build that cannot be produced.

## Repository structure

```text
shipguard/
├── SKILL.md                     # Agent audit workflow
├── checks/
│   └── core-checks.md           # Baseline production checks
├── references/
│   └── scoring.md               # 100-point scoring model + blocker rules
├── scripts/
│   └── collect_evidence.py      # Deterministic static evidence collector
├── tests/
│   └── test_collect_evidence.py # Local unit tests
├── evals/
│   └── cases.json               # Behavioral evaluation cases
└── examples/
    └── sample-report.md         # Example audit output
```

## Quick start

Run the deterministic evidence collector against a local repository:

```bash
python scripts/collect_evidence.py /path/to/project
```

Or save the evidence as JSON:

```bash
python scripts/collect_evidence.py /path/to/project --output shipguard-evidence.json
```

On Windows PowerShell:

```powershell
py scripts\collect_evidence.py C:\path\to\project --output shipguard-evidence.json
```

The collector inspects repository-level evidence such as:

- framework and package-manager markers;
- build/test/lint/typecheck scripts;
- tracked environment files;
- secret-like assignments without exposing their values;
- database/migration markers;
- CI and deployment configuration;
- observability dependency markers.

The collector intentionally **does not** make the final readiness decision. `SKILL.md` defines the audit workflow and uses the collected evidence together with direct repository/runtime inspection.

## Run the tests

ShipGuard's evidence collector uses only the Python standard library. Run its local test suite with:

```bash
python -m unittest discover -s tests -v
```

On Windows you can use:

```powershell
py -m unittest discover -s tests -v
```

## Evidence model

Every finding should use one of three confidence states:

- `CONFIRMED` — directly supported by code, configuration, runtime output, schema, policy, or dependency metadata.
- `LIKELY` — strongly indicated, but one verification step is still missing.
- `NOT VERIFIED` — insufficient evidence; report as a gap rather than a failure.

This keeps the final report auditable and reduces false certainty.

## Example output

```text
Production Readiness Score: 78/100
Decision: BLOCKED

Critical
SG-001  Cross-tenant record access
         CONFIRMED · Security

High
SG-002  Password-reset abuse protection not fully verified
         LIKELY · Security

Medium
SG-003  Missing index on orders.customer_id
         CONFIRMED · Database
```

See [`examples/sample-report.md`](examples/sample-report.md) for a complete report.

## Current scope

ShipGuard is being built first for modern web application repositories, with an initial focus on stacks such as Next.js, React, TypeScript, Supabase/PostgreSQL, and common deployment platforms. The audit rules remain evidence-driven so additional stacks can be added without changing the core decision model.

## Design principles

1. **Evidence before scoring.** Never deduct points from assumptions.
2. **Blockers override scores.** Critical launch risk cannot be averaged away.
3. **Static analysis is not production truth.** Cloud/runtime controls may exist outside the repository.
4. **Remediation must be actionable.** Each finding should state impact, evidence, fix, and verification.
5. **Positive controls matter.** A good audit reports what is working, not only what is broken.

## Status

Early development / MVP. The scoring model, baseline check catalog, evaluation fixtures, sample report, deterministic evidence collector, and local unit tests are implemented. Executable stack-specific checks and automated evaluation are next.

## License

MIT
