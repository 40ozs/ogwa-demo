# Authorization

This document covers how the operator API authenticates people, which roles exist, what
each role may do, how separation of duties is enforced, and what this build refuses
outright. The API contract is in [../architecture/api.md](../architecture/api.md). The
binding owner decisions are D46–D51 in [../architecture/decisions.md](../architecture/decisions.md).

## Principles

1. **Roles come from deployment configuration, never from the request.** A role is granted
   only by a role binding that names a **stable identity-provider group id** (D47). The
   bindings are loaded at startup and cannot be changed through the API (D48).
2. **Read, review, approval, and execution are separate permissions.** No role holds
   two of the conflicting ones, and the role table in code is pinned by tests.
3. **Four-eyes is per action and per principal (D49).** A person who holds several roles
   still cannot approve what they submitted, or plan the dry run of what they approved.
4. **No permission bypasses the evidence rules.** An approval or a dry-run plan is accepted
   only if the lifecycle guard of the step it would authorize passes.
5. **Execution is dry-run planning only.** `PRODUCTION_MUTATION` is refused before any
   other check, for everyone (D8).

## Authentication

```text
credential ──▶ IdentityAdapter.authenticate() ──▶ PrincipalClaims(issuer, subject, groups)
                                                         │
                         RoleBindings.roles_for(claims) ◀─┘   (issuer must match; group ids only)
                                                         │
                                  Principal(claims, roles) ──▶ permissions (fixed table)
```

- **Adapter boundary (D51).** `IdentityAdapter` is the only place an identity provider
  plugs in. It returns verified claims: a stable `subject` (which becomes the audit actor
  id) and stable group ids.
- **This build has exactly one adapter: `SyntheticIdentityAdapter`.** It signs in a
  principal listed in `config/synthetic-idp.json` with no password, and it refuses to be
  constructed unless the mode is `LOCAL_SYNTHETIC` and the store is marked SYNTHETIC (D50).
  It accepts only synthetic-shaped identifiers (`synthetic.*` subjects, `00gSYNTH*` group
  ids).
- **No header trust.** No code path reads identity from a request header
  (`X-Remote-User`, `X-Forwarded-User`, and similar). Any `Authorization` header is
  refused with `401 UNSUPPORTED_AUTHENTICATION`.
- **No token verification yet.** There is no JWT or OIDC verification until an approved
  verification library or service exists (D51). The API refuses to start in any mode other
  than `LOCAL_SYNTHETIC`, so there is no production authentication path to misconfigure.

### Sessions and CSRF

| Control | Implementation |
| --- | --- |
| Cookie | `__Host-ogwa-session`: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain` |
| Token | 256-bit random. The server stores only its SHA-256, so the session table cannot be replayed |
| Fixation | Every sign-in issues a new token and revokes any token presented with it |
| Expiry | 15 minutes idle and 8 hours absolute, on a monotonic clock |
| CSRF | A per-session token, returned at sign-in and by `GET /session`, is required in `X-OGWA-CSRF` on every authenticated `POST` and compared in constant time |
| Origin | A `POST` with an `Origin` other than the server's own, or with `Sec-Fetch-Site` of `cross-site`/`same-site`, is refused (`ORIGIN_REFUSED`). This also covers sign-in (login CSRF) |
| Media type | Bodies must be `application/json`, which a cross-site HTML form cannot send without a CORS preflight. OGWA answers no preflight and sends no CORS headers |
| Logout | `POST /session/logout` (CSRF required) revokes the session and expires the cookie |

## Roles

D46 defines `IDENTITY_AUTOMATION` and `SECURITY_IAM`; D59 keeps `VIEWER`, `EXECUTOR`, and
`ADMINISTRATOR`. Deployments name their own IdP groups; only the binding from group id to
OGWA role is fixed.

| Role | Purpose |
| --- | --- |
| `VIEWER` | **Strictly read-only (D60):** the inventory, candidates, evidence, decisions, approvals, jobs, and collectors |
| `IDENTITY_AUTOMATION` | Propose and advance: submit candidates for review, lift blocks, select mapping pairings, stop candidates |
| `SECURITY_IAM` | Approve or reject lifecycle stages and mapping pairings, stop candidates |
| `EXECUTOR` | **Only (D61):** plan dry runs for a stage already approved by someone else, and record the dry-run step. No mapping, policy, or approval power |
| `ADMINISTRATOR` | **Operational and configuration concerns only (D62):** read the audit chain, the role bindings, and store integrity. No lifecycle, review, approval, or execution power, and nothing is inherited from the role (D63) |

Code checks permissions, never role names. `test_nothing_is_inherited_from_a_role_name`
fails if any API module other than the role table refers to a role, so no role can imply
another role's powers.

### Permissions

| Permission | VIEWER | IDENTITY_AUTOMATION | SECURITY_IAM | EXECUTOR | ADMINISTRATOR |
| --- | :-: | :-: | :-: | :-: | :-: |
| `READ_INVENTORY` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `READ_AUDIT` | | ✓ | ✓ | | ✓ |
| `READ_SYSTEM` | | | | | ✓ |
| `MAPPING_PROPOSE` (inspect, bounded search, select) | | ✓ | | | |
| `MAPPING_APPROVE` | | | ✓ | | |
| `MAPPING_REJECT` | | ✓ | ✓ | | |
| `LIFECYCLE_ADVANCE` (forward without approval; re-entry) | | ✓ | | | |
| `LIFECYCLE_DIVERT` (to a safer state) | | ✓ | ✓ | | |
| `APPROVAL_DECIDE` | | | ✓ | | |
| `EXECUTION_PLAN_DRY_RUN` | | | | ✓ | |
| `EXECUTION_EXECUTE` (real execution) | | | | | |

The table is `ROLE_PERMISSIONS` in `app/api/authz.py`. `RoleModelTests` pin these
properties:

- no role holds both `APPROVAL_DECIDE` and `EXECUTION_PLAN_DRY_RUN`;
- no role holds both `LIFECYCLE_ADVANCE` and `APPROVAL_DECIDE`;
- no role holds both `MAPPING_PROPOSE` and `MAPPING_APPROVE`;
- `VIEWER` holds only `READ_INVENTORY`;
- `ADMINISTRATOR` holds no write permission;
- no role holds `EXECUTION_EXECUTE`.

### Lifecycle steps

| Step | Permission |
| --- | --- |
| `DISCOVERED → CANDIDATE`, `CANDIDATE → NEEDS_REVIEW`, `HOLD → REVALIDATION_REQUIRED`, `QUARANTINE_HOLD → DELETION_REVALIDATION_REQUIRED`, re-entry from a blocked state | `LIFECYCLE_ADVANCE` |
| `DELETION_REVALIDATION_REQUIRED → DELETION_PROPOSED` (the deletion proposal) | `LIFECYCLE_ADVANCE`, and a human; the proposer is recorded |
| Any move to a safer state (`BLOCKED`, `EXCLUDED`, `REJECTED`, …) | `LIFECYCLE_DIVERT` |
| `NEEDS_REVIEW → APPROVED`, `REVALIDATION_REQUIRED → QUARANTINE_APPROVED`, `DELETION_PROPOSED → DELETION_APPROVED` | `APPROVAL_DECIDE` (and the domain requires the approver themself) |
| `APPROVED → OKTA_UNASSIGN_DRY_RUN`, `QUARANTINE_APPROVED → QUARANTINE_DRY_RUN`, `DELETION_APPROVED → DELETION_DRY_RUN` | `EXECUTION_PLAN_DRY_RUN` |
| `OKTA_UNASSIGN_DRY_RUN → HOLD`, `QUARANTINE_DRY_RUN → QUARANTINE_HOLD`, `DELETION_DRY_RUN → RETIRED` | **No operator.** These record that read-only discovery observed an approved change |
| `REVALIDATION_REQUIRED → RETIREMENT_DRY_RUN`, `RETIREMENT_DRY_RUN → RETIRED` | **No operator.** The legacy single AD stage, history only (D148): `409 LEGACY_AD_RETIREMENT` |

`test_every_lifecycle_transition_has_an_explicit_operator_rule` checks that every pair in
the lifecycle's transition table has a rule.

## Role bindings (D47, D48)

```json
{"format": "ogwa-role-bindings/v1", "environment": "SYNTHETIC", "issuer": "urn:ogwa:synthetic-idp",
 "bindings": [{"idpGroupId": "00gSYNTHOGWASECIAM", "role": "SECURITY_IAM", "note": "approve"}]}
```

The loader is strict:

- The `environment` must equal the store's environment marker.
- The `issuer` must equal the identity adapter's, or the API refuses to start. Claims from
  any other issuer get no roles.
- A binding that names a group by display name (`displayName`, `groupName`, `name`,
  `group`) is refused with an explicit D47 message. Unknown roles, unknown keys, and
  duplicate bindings are refused.
- The synthetic IdP deliberately contains a group whose display name equals the Security
  IAM group's but whose id differs. Its member gets no role
  (`test_a_group_with_a_matching_display_name_grants_nothing`).

No route writes bindings. Administrators can read them (`GET /system/role-bindings`,
`editable: false`). Production bindings are a deployment artefact that will arrive with a
real identity provider (D47 group ids are an open owner question).

## Separation of duties

The services enforce these rules per action, whatever roles the principal holds.

| Action | The principal must not be | Rule |
| --- | --- | --- |
| Approve or reject a stage | The candidate's proposer | A-4 (domain) and the API |
| Approve or reject `OKTA_UNASSIGN` | The person who moved the candidate into `NEEDS_REVIEW` in this epoch | D49 (API) |
| Approve or reject `AD_QUARANTINE` | The person who moved it into `REVALIDATION_REQUIRED` in this epoch, or the `OKTA_UNASSIGN` approver | D49 (API), D11 (domain and API) |
| Approve or reject `AD_DELETION` | The deletion's proposer, the `AD_QUARANTINE` approver, or the `OKTA_UNASSIGN` approver | D143 (domain, API, remediation gates, history replay) |
| Plan a dry run, or record the dry-run step | The approver of that stage | D49 (API) |
| Request a remediation dry run | The approver of that stage | D49 (API, and the `SEPARATION_OF_DUTIES` remediation gate) |
| Approve a mapping pairing | The person who selected it | C-10 (domain chain rule and database trigger) |
| Use a mapping search result | Anyone but the person who ran the search | API |

`test_the_submitter_cannot_approve_even_holding_both_roles` covers a principal holding
both `IDENTITY_AUTOMATION` and `SECURITY_IAM`. `test_the_approver_cannot_plan_or_record_the_dry_run`
covers one holding both `SECURITY_IAM` and `EXECUTOR`.

## Evidence rules cannot be bypassed

- **Approvers.** Before an `APPROVE` is recorded, the API evaluates the lifecycle guard of
  the step it would authorize, with the draft approval in place:
  - for `OKTA_UNASSIGN`, `NEEDS_REVIEW → APPROVED`;
  - for `AD_QUARANTINE`, `REVALIDATION_REQUIRED → QUARANTINE_APPROVED`;
  - for `AD_DELETION`, `DELETION_PROPOSED → DELETION_APPROVED`.

  If the guard refuses, nothing is recorded (`EVIDENCE_RULES_NOT_MET`). So a name-only or
  unverified mapping, a protected group, a blocking dependency, stale evidence, or
  less-than-COMPLETE dependency coverage for an AD stage cannot be approved. The legacy
  `AD_RETIREMENT` stage cannot be approved at all (`LEGACY_AD_RETIREMENT`, D148).
- **Executors.** A dry run is planned only if all of these hold:
  - the approval is valid now (`approval_problems`: stage, epoch, decision, expiry, after
    the hold, a different approver from the earlier stage);
  - its fingerprint equals the current evidence;
  - the guard of the dry-run step passes, including the 24-hour execution freshness
    ceiling (E-3).
- **Everyone.** Every forward action names the evidence fingerprint the operator looked
  at. If the evidence changed since, the action is refused (`EVIDENCE_CHANGED`).

## Production mutation

- `dryRun: false` or `executionMode: "PRODUCTION_MUTATION"` on a plan request is refused
  with `PRODUCTION_MUTATION_REFUSED` before any other check. Any other mode name is
  `VALIDATION_FAILED`.
- `POST /execution-jobs/{jobId}/execute` refuses every principal, even one whose role
  were patched to hold `EXECUTION_EXECUTE` (`test_execute_route_refuses_everyone_even_with_the_permission`).
  Its static permission is `EXECUTION_PLAN_DRY_RUN` or `EXECUTION_EXECUTE`: an executor is
  refused by the build (`PRODUCTION_MUTATION_REFUSED`, chained); anyone else cannot use the
  route at all (`FORBIDDEN`, security log only).
- `DryRunPlanner` is a `MutationCapableService` whose policy is `DRY_RUN_MUTATION`, which
  can only answer `PLAN_ONLY`. Its operation callback raises if it is ever invoked.
- Planning refuses any process mode that cannot record jobs
  (`EXECUTION_MODE_NOT_AUTHORIZED`). The API itself refuses to start outside
  `LOCAL_SYNTHETIC`.
- `BUILD_ALLOWS_PRODUCTION_MUTATION` is `False`, and the build has no outbound client:
  `app/api` imports no HTTP client, socket, or integration module (`NoOutboundClientTests`,
  `test_api_imports_no_network_mutation_or_integration_module`).
- **Remediation dry runs** use the same permission, `EXECUTION_PLAN_DRY_RUN`. They have no
  permission or role of their own.
  - `POST /candidates/{id}/remediation-dry-runs` refuses `PRODUCTION_MUTATION` and
    `dryRun: false` first.
  - It answers only `SIMULATED` or `VALIDATION_ONLY`, or `409 REMEDIATION_BLOCKED`.
  - Granting every permission to every role changes none of this
    (`test_even_every_permission_cannot_turn_a_dry_run_into_an_execution`).
  - No permission overrides protection
    (`test_no_field_role_or_permission_overrides_protection`).

  See [mutation-gates.md](mutation-gates.md).

## Recording refusals (D64, D65; confirmed by D72, D73)

| Refusal | Recorded in |
| --- | --- |
| Unauthenticated (401); CSRF or Origin refusal; a route's **static** permission refusal (the principal's roles cannot use that route at all, decided before the request body is read); malformed or invalid input; unknown resource | API security log only (`api.refused` for 401/403) |
| A lifecycle guard refusal | Audit chain, `TRANSITION_REFUSED` (by the store) |
| Any other 403 or 409 on a governed state-changing route, after authentication, CSRF, the static permission, and body validation passed (four-eyes, evidence rules, approval validity, stale view, wrong state, production mutation, a per-transition permission, a refused mapping review) | Audit chain, `GOVERNED_REQUEST_REFUSED` (migration 0007): the human actor, the subject id, the request id as correlation id, the code, the problems, and the request's structured fields. Free-text reasons are not kept, and everything is redacted |

Where the line falls (confirmed by the owner, D72): a viewer who posts to the approval
route, or anyone but an executor who posts to the execute route, is refused by the route's
static permission, a generic authorization failure, and it is logged. An approver whom
four-eyes refuses, an automation user asking for a transition only an approver may make, or
an executor asking to execute, was authorized to use the route and made a valid request
that lifecycle, policy, evidence, or separation-of-duties rules refused; that is chained.
The error then carries `auditEventId`. Ordinary route-level authorization failures are
never chained (D73). The execute route is gated statically like every other governed
route.

The chain grows only with authenticated humans' valid requests. A burst of them is
visible in the chain itself (actor, time, and request id).

## Logging

Each request writes one structured line (`api.request`: request id, method, route pattern,
status, principal subject, elapsed time). Each 401 or 403 also writes `api.refused` at
WARNING, with the error code and principal. Neither line carries query strings, bodies,
cookies, or CSRF tokens, and all lines pass through the redacting formatter.
Unexpected exceptions, including a failure to chain a refusal (`api.refusal_audit_failed`;
the refusal still stands), are logged redacted, server-side only.

## Limits and open questions

1. **No real identity provider.** Production use needs an approved token-verification
   library or service (D51), the real IdP group ids for each role (D47), and a hosting
   decision (TLS, a reviewed WSGI server, a shared session store).
2. **Sign-in rate limiting** is absent. Synthetic sign-in has no secret to guess; a real
   adapter must rely on the IdP's own controls.
