# ShipGuard Scoring Model

ShipGuard reports two independent outputs:

1. a numeric **Production Readiness Score** from 0 to 100;
2. a launch decision: **READY**, **NEEDS WORK**, or **BLOCKED**.

The launch decision is authoritative. A high numeric score never overrides a verified launch blocker.

## Category weights

| Category | Weight |
| --- | ---: |
| Security | 30 |
| Reliability | 20 |
| Database & Data Integrity | 15 |
| Deployment & Configuration | 15 |
| Observability | 10 |
| Performance | 10 |
| **Total** | **100** |

Each category starts at its full weight. Verified findings deduct points according to severity and confidence.

## Severity deductions

Use these default deductions unless a check defines a more specific value.

| Severity | Deduction | Meaning |
| --- | ---: | --- |
| Critical | entire affected category, minimum 10 points overall | Exploitable security failure, likely data loss, authorization bypass, exposed secret, destructive production risk, or another condition that must block launch |
| High | 5-10 | Serious production risk requiring remediation before normal launch |
| Medium | 2-4 | Material weakness that should be fixed but may not independently block launch |
| Low | 0.5-1 | Hardening, maintainability, or operational quality issue |
| Info | 0 | Observation, positive control, or non-scoring recommendation |

Never deduct below zero within a category.

## Evidence confidence

Every scoring finding must have a confidence state:

- `CONFIRMED`: directly supported by code, configuration, runtime output, schema, policy, or dependency metadata.
- `LIKELY`: strongly indicated but missing one verification step.
- `NOT VERIFIED`: insufficient evidence.

Only `CONFIRMED` findings receive full deductions.

`LIKELY` findings receive 50% of the normal deduction and must not independently trigger `BLOCKED` unless there is direct evidence of an active exploit or exposed production asset.

`NOT VERIFIED` findings receive no deduction. Report them separately as verification gaps.

## Automatic launch blockers

Any confirmed item below forces the launch decision to `BLOCKED`, regardless of numeric score:

- committed or exposed production secret, private key, privileged database credential, or service-role credential;
- authentication bypass on a protected production path;
- authorization failure allowing one user or tenant to access or mutate another user's or tenant's protected data;
- missing or ineffective row-level/data-access controls on sensitive multi-tenant data when clients can directly query that data store;
- unauthenticated privileged/admin operation;
- destructive production migration or deployment step with a credible data-loss path and no safe rollback;
- known critical dependency vulnerability that is reachable in the deployed application and has no mitigation;
- production configuration that routes sensitive data to an unintended public destination;
- verified path that permits arbitrary code execution, arbitrary file access, or equivalent critical compromise;
- a release/build artifact that cannot be produced or started in the stated production environment.

Do not create blockers from best-practice gaps alone.

## Launch decision thresholds

After blocker evaluation, use the numeric score:

| Score | Decision | Interpretation |
| --- | --- | --- |
| 90-100 | READY | No confirmed blockers and no unresolved high-severity launch risks |
| 75-89.5 | NEEDS WORK | Deployable only with explicit risk acceptance or after targeted remediation |
| 0-74.5 | BLOCKED | Production readiness is insufficient |

A confirmed `Critical` finding always results in `BLOCKED`.

A confirmed `High` finding may result in `NEEDS WORK` or `BLOCKED` depending on impact. If it creates a realistic confidentiality, integrity, availability, or release-failure risk at launch, prefer `BLOCKED`.

## Category guidance

### Security — 30

Evaluate:

- secret handling and accidental credential exposure;
- authentication enforcement;
- authorization and role checks;
- tenant isolation;
- database/storage access policies;
- unsafe server-side trust in client input;
- injection-prone dynamic queries or commands;
- vulnerable dependency exposure;
- security headers where relevant;
- rate limiting/abuse protection on sensitive endpoints;
- privileged API surface.

### Reliability — 20

Evaluate:

- error boundaries and server error handling;
- retries, timeouts, idempotency, and duplicate-action protection;
- background job failure behavior;
- transaction boundaries for multi-step writes;
- graceful handling of dependency failure;
- startup/runtime failure conditions;
- rollback and recovery paths;
- critical test coverage where evidence exists.

### Database & Data Integrity — 15

Evaluate:

- migration safety;
- constraints and foreign keys;
- destructive schema changes;
- indexing for critical query paths;
- transaction correctness;
- nullability/default assumptions;
- tenant scoping;
- backup/recovery evidence when supplied;
- data retention/deletion behavior when relevant.

### Deployment & Configuration — 15

Evaluate:

- production build success;
- runtime compatibility;
- environment-variable validation;
- production/dev separation;
- deployment manifest/configuration;
- CI/CD release gates where present;
- health checks;
- rollback strategy;
- migration ordering;
- required external services.

### Observability — 10

Evaluate:

- structured error logging;
- exception monitoring;
- request/job correlation where relevant;
- health/uptime visibility;
- actionable alerts;
- audit logging for privileged or high-risk operations;
- secret/PII leakage in logs.

### Performance — 10

Evaluate:

- obvious N+1 or unbounded query patterns;
- missing pagination on large collections;
- missing indexes on critical paths;
- uncontrolled concurrency;
- blocking work on request paths;
- caching opportunities only where a real bottleneck is evidenced;
- bundle/server rendering problems when measurable;
- oversized payloads or repeated remote calls.

## Scoring procedure

1. Determine which categories are applicable.
2. Collect evidence before assigning findings.
3. Classify each finding by severity and confidence.
4. Apply deductions within the relevant category.
5. Calculate the 0-100 score.
6. Evaluate automatic blockers independently.
7. Produce the launch decision.
8. List `NOT VERIFIED` areas separately; never silently count them as passing.

## Required report fields

Every scored report must include:

- overall score;
- launch decision;
- category score breakdown;
- confirmed blockers;
- prioritized findings;
- evidence for each finding;
- remediation guidance;
- verification gaps;
- positive controls that materially reduce risk.

## Guardrails

- Never award points merely because a file name suggests a control exists.
- Never infer deployed infrastructure from local configuration alone.
- Never treat absence of evidence as evidence of absence.
- Never mark a category as fully verified when critical runtime or production configuration is unavailable.
- Prefer a lower confidence state instead of inventing certainty.