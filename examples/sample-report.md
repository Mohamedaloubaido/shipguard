# ShipGuard Production Readiness Report

> Example output. Findings below are illustrative and do not describe a real repository.

## Executive summary

**Score:** 78 / 100  
**Decision:** `BLOCKED`  
**Reason:** A confirmed tenant-isolation failure creates a launch blocker even though several production controls are already in place.

## Score breakdown

| Category | Score | Weight |
| --- | ---: | ---: |
| Security | 15 | 30 |
| Reliability | 17 | 20 |
| Database & Data Integrity | 12 | 15 |
| Deployment & Configuration | 14 | 15 |
| Observability | 10 | 10 |
| Performance | 10 | 10 |
| **Total** | **78** | **100** |

## Launch blockers

### SG-001 — Cross-tenant record access

**Severity:** Critical  
**Confidence:** CONFIRMED  
**Category:** Security

**Evidence**

- `app/api/projects/[id]/route.ts` checks that a session exists but does not verify project membership.
- The query fetches a project directly by the route-supplied ID.
- The inspected database policy permits authenticated reads without tenant membership filtering.

**Impact**

An authenticated user can request a project ID belonging to another tenant and receive protected project data.

**Remediation**

Enforce tenant membership server-side before the query and apply tenant-scoped database policies so authorization does not depend on route code alone.

**Verification after fix**

- add a negative integration test using two tenants;
- verify tenant A cannot read or mutate tenant B records;
- inspect the effective production data-access policy.

## High-priority findings

### SG-002 — Password reset endpoint has unverified abuse protection

**Severity:** High  
**Confidence:** LIKELY  
**Category:** Security

**Evidence**

The application route contains no rate limiter. Deployment-platform or edge-level rate limiting was not provided for inspection.

**Remediation**

Verify upstream protection. If none exists, add IP/account-aware throttling and abuse monitoring for reset attempts.

## Medium findings

### SG-003 — Missing index on `orders.customer_id`

**Severity:** Medium  
**Confidence:** CONFIRMED  
**Category:** Database & Data Integrity

**Evidence**

The order-history query filters by `customer_id`, while inspected migrations contain no supporting index.

**Remediation**

Add an index through a safe migration and compare the query plan before and after the change.

## Positive controls

- Production build succeeds.
- Runtime environment variables are validated at startup.
- Error monitoring is initialized server-side.
- Deployment health check is configured.
- Critical multi-step payment write uses a database transaction.

## Verification gaps

These items were not counted as failures:

- production backup/restore procedure was not supplied;
- upstream WAF/rate-limit configuration was not available;
- production alert-routing rules were not available.

## Recommended release plan

1. Fix SG-001 and add a cross-tenant regression test.
2. Re-run the security and database checks.
3. Verify upstream abuse protection for authentication endpoints.
4. Add the missing database index and inspect its production migration plan.
5. Recalculate the score and launch decision.

## Final decision

`BLOCKED`

The application should not be released until the confirmed tenant-isolation vulnerability is remediated and verified. The numeric score does not override this blocker.
