# Credential handling

This build reads no credential. It includes no Okta, Active Directory, or AAP integration
and no outbound client, so there is nothing for a credential to authenticate to, and
`Settings` has no field that could hold one. Synthetic sign-in needs no password
([authorization.md](authorization.md)).

## Rules

- No credential ever appears in source, `.env.example`, tests, fixtures, logs, reports,
  screenshots, or tickets.
- OGWA reads its configuration from the process environment only. It does **not**
  auto-load `.env` files and has no command-line parameter for secrets.
- Startup refuses credential variables (below). Error messages name variables, never
  values.
- Secrets never appear in logs. `Secret` (`app/core/secret.py`) renders as `***`, refuses
  pickling and copying, and registers its value so the log formatter scrubs it verbatim;
  `app/core/redaction.py` also scrubs credential-shaped text and credential-named fields
  from log lines and audit details.
- Diagnostics and the startup banner carry no credential field.
- Browser code never holds Okta, AAP, or AD credentials.

## Refused at startup

`app/core/config.py` refuses to start, with "This public build supports Demo Mode only.
Live integrations are unavailable.", when any of these is set:

| Variables | Why |
| --- | --- |
| `OGWA_OKTA_ORG_URL`, `OGWA_OKTA_API_TOKEN`, `OGWA_AAP_URL`, `OGWA_AAP_TOKEN`, `OGWA_HTTP_*` | They configured live integrations and an outbound transport that this build does not include |
| `OKTA_API_TOKEN`, `OKTA_CLIENT_TOKEN`, `OKTA_CLIENT_SECRET`, `OKTA_CLIENT_PRIVATEKEY`, `OKTA_PRIVATE_KEY`, `CONTROLLER_PASSWORD`, `CONTROLLER_OAUTH_TOKEN`, `TOWER_PASSWORD`, `TOWER_OAUTH_TOKEN`, `AAP_TOKEN`, `AD_BIND_PASSWORD`, `LDAP_BIND_PASSWORD` | Credential variables of other Okta, AAP/AWX, and AD tooling. OGWA never reads them; their presence means production credentials reached a demo process |
| Any other unrecognised `OGWA_*` key | A typo or an attempted override must not silently change behaviour |

`tests/test_runtime_mode.py` (`test_live_credentials_are_refused_without_echoing_them`) and
`tests/test_config_and_secrets.py` (`test_config_errors_do_not_echo_secret_values`) check
that a refusal never repeats the value.

The credential decisions for a live deployment (D6, D123–D126) are recorded in
[../architecture/decisions.md](../architecture/decisions.md). None of them applies to this
build.

## The hosted demo's session key

The hosted demo's only secret is `HOSTED_SESSION_KEY`, the key that signs its session
cookies (at least 64 hex digits). It is set as a Cloudflare Worker secret and never
committed. Without a usable key the Worker serves nothing, and its log names the secret,
never its value. See [../deployment/cloudflare-demo.md](../deployment/cloudflare-demo.md).

## Sensitive local files

`.gitignore` excludes `.env*` (except `.env.example`), Wrangler's local secret files
(`.dev.vars*`), token caches, keys and certificates, local databases (`*.db`, `*.sqlite*`,
`var/`, `data/`), generated evidence and exports (`evidence/`, `exports/`, `reports/`,
`*.csv`, `*.xlsx`), and logs. Synthetic CSV fixtures under `tests/fixtures/` are the only
CSVs allowed in source control.

## If a secret leaks

1. Revoke or rotate it through the owning team's process. Do not do this from OGWA.
2. Remove it from the working tree. If it reached Git history, treat it as compromised
   regardless of history rewriting.
3. Record the incident without repeating the secret.
