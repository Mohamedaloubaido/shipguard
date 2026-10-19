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
├── SKILL.md
├── checks/
│   ├── core-checks.md
│   └── nextjs-supabase.md
├── references/
│   └── scoring.md
├── scripts/
│   ├── collect_evidence.py
│   ├── analyze_next_supabase.py
│   └── score_findings.py
├── tests/
│   ├── test_collect_evidence.py
│   ├── test_next_supabase.py
│   └── test_score_findings.py
├── evals/
│   └── cases.json
└── examples/
    ├── findings.json
    └── sample-report.md
```

## Quick start

Run the deterministic evidence collector:

```bash
python scripts/collect_evidence.py /path/to/project --output shipguard-evidence.json
```

On Windows PowerShell:

```powershell
py scripts\collect_evidence.py C:\path\to\project --output shipguard-evidence.json
```

The collector inspects repository-level evidence such as framework markers, package scripts, tracked environment files, secret-like assignments, database/migration markers, CI/deployment configuration, and observability dependencies.

## Next.js + Supabase analyzer

ShipGuard includes a stack-specific analyzer for Next.js applications using Supabase:

```bash
python scripts/analyze_next_supabase.py /path/to/project --output next-supabase-report.json
```

On Windows:

```powershell
py scripts\analyze_next_supabase.py C:\path\to\project --output next-supabase-report.json
```

Current checks include:

- public exposure of Supabase service-role credentials;
- service-role references from Client Components;
- Supabase migration tables without detected RLS enablement;
- mutating App Router Route Handlers where authentication cannot be verified locally;
- `dangerouslySetInnerHTML` usages requiring sanitization review.

The analyzer deliberately distinguishes `CONFIRMED`, `LIKELY`, and `NOT VERIFIED` results. Missing repository evidence is not automatically treated as proof of a production defect.

## Deterministic scoring

After findings are verified and classified, calculate the final score and launch decision without relying on model arithmetic:

```bash
python scripts/score_findings.py examples/findings.json
```

On Windows:

```powershell
py scripts\score_findings.py examples\findings.json
```

A scoring input contains findings such as:

```json
{
  "id": "DB-002",
  "category": "Database & Data Integrity",
  "severity": "Medium",
  "confidence": "CONFIRMED",
  "blocker": false
}
```

`Critical + CONFIRMED` findings automatically block launch. An explicitly verified blocker also overrides the numeric score.

## Run the tests

ShipGuard's helper scripts use only the Python standard library:

```bash
python -m unittest discover -s tests -v
```

On Windows:

```powershell
py -m unittest discover -s tests -v
```

## Evidence model

Every finding uses one of three confidence states:

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

## Design principles

1. **Evidence before scoring.** Never deduct points from assumptions.
2. **Blockers override scores.** Critical launch risk cannot be averaged away.
3. **Static analysis is not production truth.** Cloud/runtime controls may exist outside the repository.
4. **Remediation must be actionable.** Each finding should state impact, evidence, fix, and verification.
5. **Positive controls matter.** A good audit reports what is working, not only what is broken.

## Status

MVP implemented. ShipGuard currently includes a deterministic evidence collector, a deterministic scoring engine, a Next.js + Supabase analyzer, a baseline check catalog, stack-specific checks, behavioral eval fixtures, sample reports, and local unit tests.

## License

MIT
