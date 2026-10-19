# Next.js + Supabase checks

These checks are implemented by `scripts/analyze_next_supabase.py`.

ShipGuard uses conservative confidence labels:

- `CONFIRMED` — direct repository evidence supports the finding.
- `LIKELY` — repository evidence indicates a meaningful risk, but runtime/live-state verification is still required.
- `NOT VERIFIED` — ShipGuard could not establish the control from the inspected source. This is a verification gap, not proof of a vulnerability.

## NS-SEC-001 — Public service-role credential

**Severity:** Critical  
**Confidence:** Confirmed  
**Blocker:** Yes

Trigger when application source references a credential identifier that combines Next.js `NEXT_PUBLIC_` exposure with a Supabase service-role name.

Why it matters: `NEXT_PUBLIC_` values are designed to be exposed to client-side code. Supabase service-role credentials bypass normal Row Level Security and must never be distributed to browsers.

Required remediation:

1. remove the public variable;
2. rotate the affected credential if exposure may have occurred;
3. move privileged operations into server-only code;
4. verify the client receives only anon/publishable credentials.

## NS-SEC-002 — Service role in a Client Component

**Severity:** Critical  
**Confidence:** Confirmed  
**Blocker:** Yes

Trigger when a file marked with `use client` references a service-role credential identifier.

A Client Component can be included in browser-delivered code. Privileged Supabase credentials belong exclusively in trusted server-side execution.

## NS-SEC-003 — Raw HTML rendering

**Severity:** Medium  
**Confidence:** Likely  
**Blocker:** No

Trigger on `dangerouslySetInnerHTML`.

This is not automatically an XSS vulnerability. The finding requires verification of the HTML source and sanitization/data-flow controls.

## NS-AUTH-001 — Mutating Route Handler authentication gap

**Severity:** Medium  
**Confidence:** Not Verified  
**Blocker:** No

Trigger when an App Router API Route Handler exports `POST`, `PUT`, `PATCH`, or `DELETE`, but the same file contains no recognized authentication marker.

This intentionally does **not** assert that the route is unauthenticated. Authentication may be enforced by middleware, a wrapper, an upstream gateway, or another mechanism. Reviewers must verify the effective control before converting the gap into a confirmed finding.

## NS-DB-001 — Supabase table without RLS enablement in migrations

**Severity:** High  
**Confidence:** Likely  
**Blocker:** No by default

Trigger when scanned Supabase/migration SQL creates an application table and ShipGuard cannot find an `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` statement for the table anywhere in the scanned migration set.

The finding describes repository evidence only. The live database may differ, so production state must be verified before treating the result as confirmed.

If live verification proves that a client-accessible table is exposed without required RLS, the reviewer may escalate the result to `CONFIRMED` and, when cross-tenant or sensitive data exposure is possible, to a launch blocker.

## Non-goals

The analyzer does not currently prove:

- effective live RLS policy behavior;
- Supabase project dashboard configuration;
- rate limiting or WAF behavior provided outside the repository;
- authorization correctness across arbitrary helper abstractions;
- whether raw HTML is attacker-controlled;
- whether a credential is active.

Those require runtime, infrastructure, or data-flow evidence.
