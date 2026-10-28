"""Remediation (P10): the future execution path for Okta and AD changes, dry-run only.

- ``app.domain.remediation``: operations, outcomes, gates, and the result record (pure).
- ``allowlist``: the server-side configuration that decides what answers each operation.
- ``adapters``: the synthetic and AAP adapters; both can only plan (DRY_RUN_MUTATION).
- ``aap``: AAP job-template metadata and its safety classification.
- ``worker``: the JSON contract with the PowerShell worker ``worker/OGWA.Remediation``.
- ``engine``: one dry run end to end.
- ``quarantine``: loads the deployment-controlled quarantine OU configuration (P10B, D136).

Every request resolves to SIMULATED, WHATIF, VALIDATION_ONLY, or BLOCKED. Nothing in this
package imports an HTTP client, a process module, or the mutating client. See
docs/architecture/remediation.md and docs/security/mutation-gates.md.
"""
