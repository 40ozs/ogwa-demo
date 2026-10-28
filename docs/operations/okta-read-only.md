# Operating the Okta read-only integration

Audience: the operator or Okta administrator who will enable, probe, and later run
OGWA's Okta discovery. Design details are in
[../architecture/okta-integration.md](../architecture/okta-integration.md).

> **Current state (P04):** the client exists and is tested against mocks only. There is
> **no approved credential** and **no token-exchange code**, so OGWA cannot authenticate
> to a real Okta org yet. Nothing in this runbook can be carried out until the
> prerequisites below are met.

## Rules that always apply

- Discovery is **read-only**. The client can send only GET requests, and it refuses any
  credential that carries a write (`*.manage`) or unneeded scope.
- Never create, rotate, or revoke Okta credentials from OGWA or as part of an OGWA
  task. Credential lifecycle belongs to the Okta administrators' own process.
- Never paste a token into chat, a ticket, a file in the repository, or a command line.
  SSWS API tokens are not used at all (decision D6).
- Treat the Okta org as production. Begin with the narrowest possible read.

## Prerequisites

| # | Prerequisite | Owner | State |
| --- | --- | --- | --- |
| 1 | Token acquisition model | Project owner | **Decided (D26):** a dedicated token client whose only POST target is the configured `/oauth2/v1/token`. The resource client stays GET/HEAD-only. Not yet built |
| 2 | An approved RS256 signing mechanism: a crypto package from an org-approved source, or a vault/HSM signing service | Project owner / Security | **Outstanding.** No signing is implemented until it exists |
| 3 | Create a dedicated API service app: client credentials, `private_key_jwt`, scopes `okta.apps.read`, `okta.groups.read`, `okta.logs.read` only, and the **Read-Only Administrator** role. **Never Super Admin.** Set a low per-app rate-limit share if the tenant supports one | Okta administrator | **Outstanding.** Ask the administrator first whether a narrower custom role can satisfy every required read, including the System Log; use it only if so |
| 4 | Store the private key (or signing-key reference) in an approved secret store | Okta administrator / Security | Outstanding |
| 5 | Build the token client (after 2) and replace the `OGWA_OKTA_API_TOKEN` placeholder with the OAuth configuration | Implementing prompt | Outstanding |
| 6 | Retention versus `min_usage_window` | Project owner | **Decided (D27):** the 90-day policy stays. Native retention gives at most a shorter low-usage review signal (`REVIEW_SIGNAL_ONLY`), never a complete 90-day retirement window |

## First live read: the single-read probe

Do this once, after the prerequisites are met. Do **not** start any wider collection
because the probe worked. Full read-only collection is P11.

1. Set `OGWA_EXECUTION_MODE=READ_ONLY_PRODUCTION` and `OGWA_OKTA_ORG_URL=https://<org>.okta.com`
   for this process only.
2. Build a client with a request budget of exactly one:
   `OktaReadOnlyClient.from_settings(settings, credentials=<approved provider>, pacing=PacingPolicy(max_requests=1))`.
   `probe()` refuses any other budget, so a retry cannot turn the probe into two requests.
3. Call `probe()`. It sends exactly one request, `GET /api/v1/apps?limit=1`.
4. Record only what `ProbeResult` contains: `ok`, `http_status`, `items_returned`
   (0 or 1), `granted_scopes`, `rate_limit_remaining`, `rate_limit_limit`. It holds no
   app names or IDs.
5. Check:
   - `http_status` is 200 and `ok` is true;
   - `granted_scopes` is exactly the three read scopes (a broader grant is refused before sending);
   - rate-limit headroom is plausible for the org.
6. **Stop.** Write up the result in the run report (redact anything tenant-specific).

| Probe result | Meaning | Action |
| --- | --- | --- |
| 200, `ok` | Credential and scope work for apps read | Stop. Plan P11 |
| 401 | Token rejected (expired, wrong audience, wrong client) | Stop. Okta administrator checks the service app. Do not retry in a loop |
| 403 | Scope granted on the app but the admin role does not permit it | Stop. Okta administrator reviews the role assignment. **Do not broaden the role without review** |
| 429, or the budget is spent | The org is under rate-limit pressure | Stop. Try later. Never raise the budget to push through |
| `OktaCredentialError` before sending | The grant carries extra scopes or is expiring | Fix the credential. Do not work around the check |

Also verify one AD-imported group by hand during the first real read (P11): its
`directory_object_guid_unverified` must equal the objectGUID that AD reports. Until that
proof is recorded in a run report, `OBJECT_GUID_DECODING_VERIFIED` stays `False` and the
value never reaches domain evidence (D23, D30). The group must be AD-backed, and its
objectGUID must come independently from Active Directory, not from Okta.

## Running collections (P11 and later)

- One client per collector session. Record a `CollectorRun` before starting and the
  `CollectorRunOutcome` from `summarize_run(...).to_outcome(run_id)` at the end.
- Keep the defaults unless a reviewed reason exists: serial requests, a 0.2 s minimum
  interval, a budget of 500, and a 20% rate-limit reserve. Raising the budget is a
  reviewed change, not an operator tweak.
- Start usage collection with `UsageStrategy.PER_APPLICATION` on a handful of apps and
  a short window. Use `ORG_WIDE` only after a bounded run has shown the event volume.
- If a session halts (authentication, rate limit, or budget), do not restart it in a
  loop. Read the summary's `error_code` and `error_summary` and fix the cause.
- Raw Okta responses are never stored. Normalized records and domain evidence go into
  the store; the store is git-ignored and may hold production identifiers.

## Reading the results

- Each result has `status`: only `COMPLETE` can support a lifecycle decision.
  `PARTIAL` and `FAILED` keep whatever was seen, but provenance marks it as not
  decision-grade.
- Usage with `sign_in_count == 0` and `evidence_complete == True` means "no successful
  SSO sign-in observed in this window". It does **not** mean unused or safe to retire.
  Read `caveats`.
- `signal` says what a usage record can support. From native System Log retention it is
  at best `REVIEW_SIGNAL_ONLY`: enough to prompt a low-usage review, never enough for
  the 90-day retirement requirement.
- `incomplete_reasons` explains each gap (a failed slice, retention, ingestion lag,
  events with no actor).

## If something goes wrong

- **A token or key appears in a log, file, or chat:** follow the "If a secret leaks"
  steps in [../security/credentials.md](../security/credentials.md). Rotation is done by
  the Okta administrators, not OGWA.
- **OGWA appears to be causing rate-limit pressure:** stop the collector, check the
  run summary (`requests_attempted`, `rate_limited_responses`, `throttle_pauses`), and
  lower the budget or raise the reserve before any rerun.
- **A write was attempted or suspected:** it cannot come from this package. The client
  is GET-only, and both the tests and the HTTP layer enforce it. Investigate as a
  security incident anyway, and check Okta's System Log for the service app's client ID.
