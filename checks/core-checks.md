# ShipGuard Core Checks

This catalog defines the baseline checks ShipGuard should consider during a production-readiness audit.

A check is not automatically a failure because a repository does not expose enough evidence. Use the confidence model from `references/scoring.md`.

## Security

| ID | Check | Default severity when confirmed |
| --- | --- | --- |
| SEC-001 | Production secret or privileged credential is committed to source control | Critical |
| SEC-002 | Protected route lacks authentication enforcement | Critical |
| SEC-003 | Privileged operation lacks server-side authorization | Critical |
| SEC-004 | Cross-tenant access is possible | Critical |
| SEC-005 | Sensitive direct database access lacks effective row/data policies | Critical |
| SEC-006 | User-controlled input reaches a dangerous command/query sink without adequate controls | Critical/High |
| SEC-007 | Sensitive authentication endpoint lacks verified abuse protection | High |
| SEC-008 | Security-sensitive action trusts a client-supplied role, owner, tenant, or permission claim | High/Critical |
| SEC-009 | Known reachable dependency vulnerability has no mitigation | Based on vulnerability |
| SEC-010 | Sensitive data or credentials may be written to logs | High |

## Reliability

| ID | Check | Default severity when confirmed |
| --- | --- | --- |
| REL-001 | Critical multi-step write is non-transactional and can leave inconsistent state | High |
| REL-002 | Retryable external request has no timeout | Medium/High |
| REL-003 | Retry behavior can duplicate a non-idempotent operation | High |
| REL-004 | Background job failure is silently discarded | Medium/High |
| REL-005 | Startup depends on configuration that is not validated before serving traffic | Medium |
| REL-006 | Critical failure path has no recovery or rollback procedure | Medium/High |
| REL-007 | Production build or runtime startup fails deterministically | Critical |

## Database & Data Integrity

| ID | Check | Default severity when confirmed |
| --- | --- | --- |
| DB-001 | Destructive migration has a credible data-loss path | Critical/High |
| DB-002 | High-volume or latency-sensitive query lacks a supporting index | Medium |
| DB-003 | Data relationship relies on application convention without required integrity constraint | Medium |
| DB-004 | Tenant scope is missing from a critical data mutation/read path | Critical |
| DB-005 | Schema default/nullability assumptions conflict with application code | Medium |
| DB-006 | Concurrent mutation can violate a business invariant | High |

## Deployment & Configuration

| ID | Check | Default severity when confirmed |
| --- | --- | --- |
| DEP-001 | Production artifact cannot be built | Critical |
| DEP-002 | Required production environment variable is missing or undocumented | High/Medium |
| DEP-003 | Development/test configuration can be selected accidentally in production | High |
| DEP-004 | Runtime version differs from the version required by the application | High |
| DEP-005 | Database migration order is unsafe relative to application deployment | High |
| DEP-006 | No verified rollback path exists for a high-risk release | Medium |
| DEP-007 | Health check is missing for a service where orchestration depends on one | Medium |

## Observability

| ID | Check | Default severity when confirmed |
| --- | --- | --- |
| OBS-001 | Unhandled production errors have no verified capture path | Medium |
| OBS-002 | High-risk privileged actions lack an audit trail | High/Medium |
| OBS-003 | Logs expose secrets or unnecessary sensitive data | High |
| OBS-004 | Critical dependency failure cannot be distinguished from application failure | Medium |
| OBS-005 | Alerting for a critical production signal is absent | Medium |

## Performance

| ID | Check | Default severity when confirmed |
| --- | --- | --- |
| PERF-001 | Unbounded collection/query can grow with production data | High/Medium |
| PERF-002 | Confirmed N+1 request/query pattern exists on a critical path | Medium |
| PERF-003 | Blocking heavy work occurs synchronously on a latency-sensitive request path | Medium |
| PERF-004 | Repeated remote request could be safely deduplicated/cached and is a measured bottleneck | Low/Medium |
| PERF-005 | Critical query plan is degraded by a missing index | Medium |

## Evidence rules

For each reported finding, include:

- check ID;
- file/config/runtime source;
- concise evidence;
- severity;
- confidence;
- affected category;
- impact;
- remediation;
- verification step.

Do not report a check as failed simply because a tool, package, or filename is absent. Production controls may exist outside the repository. In those cases use `NOT VERIFIED` when the missing evidence materially matters.