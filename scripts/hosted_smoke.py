"""Smoke checks against a serving Null Meridian demo, over HTTP.

    python scripts/hosted_smoke.py https://ogwa-demo.d-walkes.workers.dev   # the hosted demo (anonymous, read-only)
    python scripts/hosted_smoke.py http://localhost:8765 --local            # a local or Docker demo

Expectations come from the dataset (its manifest and world). Exits 1 if any check fails.

The hosted demo has no sign-in: every check runs as what a visitor gets from GET /session, an
anonymous synthetic viewer, and the audit head is the dashboard's. ``--local`` signs in as the
synthetic principals instead, skips the checks only the anonymous, read-only demo passes, and
accepts that a writable demo chains each refused governed request into its audit log.
"""
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_null_meridian_demo import MANIFEST, manifest_group, okta_ref  # noqa: E402
from app.demo.null_meridian.world import CANDIDATES, EXPECTED_CONFIDENCE  # noqa: E402

ORIGIN = sys.argv[1].rstrip("/")
LOCAL = "--local" in sys.argv[2:]
V = ORIGIN + "/api/v1"
UA = "ogwa-hosted-smoke/1.0"  # Cloudflare refuses Python-urllib's default user agent (1010)
RESULTS = []


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener()
        self.csrf = self.cookie = None

    def req(self, method, url, body=None, origin=ORIGIN, headers=()):
        data = None if body is None else json.dumps(body).encode()
        r = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": UA, **dict(headers)})
        if body is not None:
            r.add_header("Content-Type", "application/json")
            if origin:
                r.add_header("Origin", origin)
        if self.csrf and method == "POST":
            r.add_header("X-OGWA-CSRF", self.csrf)
        if self.cookie:
            r.add_header("Cookie", self.cookie)
        t = time.perf_counter()
        try:
            with self.opener.open(r, timeout=60) as resp:
                status, hdrs, payload = resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            status, hdrs, payload = e.code, dict(e.headers), e.read()
        ms = round((time.perf_counter() - t) * 1000)
        for k, v in hdrs.items():
            if k.lower() == "set-cookie" and v.startswith("__Host-ogwa-session="):
                self.cookie = v.split(";", 1)[0]
        try:
            parsed = json.loads(payload)
        except ValueError:
            parsed = payload
        return status, {k.lower(): v for k, v in hdrs.items()}, parsed, ms

    def sign_in(self, subject):
        """A local demo's synthetic sign-in; the hosted demo has none."""
        s, _, _, _ = self.req("POST", f"{V}/session", {"subject": subject})
        assert s == 201, s
        self.csrf = self.req("GET", f"{V}/session")[2]["csrfToken"]

    def visit(self):
        """The public demo's only entry: GET /session gives a new visitor an anonymous session."""
        s, h, b, _ = self.req("GET", f"{V}/session")
        assert s == 200 and h.get("set-cookie", "").startswith("__Host-ogwa-session="), s
        self.csrf = b["csrfToken"]
        return b["principal"]


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


anon = Client()
s, h, b, ms = anon.req("GET", ORIGIN + "/")
check("homepage 200 + CSP", s == 200 and "require-trusted-types-for" in h.get("content-security-policy", ""), f"{s} {ms}ms")
for asset in ("/ui/js/main.js", "/ui/css/ogwa.css", "/ui/icon.svg", "/ui/js/views/directory.js",
              "/ui/js/views/findings.js", "/ui/js/present.js"):
    s, h, b, ms = anon.req("GET", ORIGIN + asset)
    check(f"static {asset} 200", s == 200 and h.get("x-ogwa-runtime-mode") == "demo", f"{s} {ms}ms")
s, h, b, ms = anon.req("GET", f"{V}/health")
check("health 200, demo, Null Meridian, seed null-meridian-v1",
      s == 200 and h.get("x-ogwa-runtime-mode") == "demo" and b["organization"] == "Null Meridian"
      and b["dataset"]["seed"] == "null-meridian-v1" and b["dataset"]["key"] == "null-meridian"
      and b["liveIntegrations"] is False and b["publicDemo"] is not LOCAL, f"{s} {ms}ms")
s, h, b, ms = anon.req("GET", f"{V}/directory")
check("no session cookie: data routes refused (401) until GET /session", s == 401, f"{s}")

viewer = Client()
if LOCAL:
    viewer.sign_in("synthetic.viewer.one")
else:
    who = viewer.visit()
    check("GET /session: an anonymous synthetic viewer, no sign-in",
          (who["subject"], who["authenticationMethod"], who["roles"], who["permissions"])
          == ("public.visitor", "anonymous-public-demo", ["VIEWER"], ["READ_INVENTORY"])
          and len(who["publicDrillCandidates"]) == 1, f"{who['subject']} {who['roles']}")
    s, h, b, ms = viewer.req("GET", f"{V}/session")
    check("the visitor keeps its session", s == 200 and b["csrfToken"] == viewer.csrf and "set-cookie" not in h, f"{s}")
    for subject in ("synthetic.viewer.one", "synthetic.executor.one", "synthetic.securityiam.one", "synthetic.admin.one"):
        s, h, b, ms = viewer.req("POST", f"{V}/session", {"subject": subject})
        check(f"no sign-in as {subject}", s == 403 and b["error"]["code"] == "PUBLIC_DEMO_NO_SIGN_IN"
              and "set-cookie" not in h, f"{s}")
for path in ("/audit-events?limit=1", "/system/integrity", "/system/role-bindings"):
    s, h, b, ms = viewer.req("GET", V + path)
    check(f"a viewer's permissions only: {path} 403", s == 403, f"{s}")
s, h, b, ms = viewer.req("GET", f"{V}/directory")
check("directory counts == manifest", s == 200 and b["counts"] == MANIFEST["counts"],
      f"{s} {ms}ms active={b.get('counts', {}).get('activeEmployees')} former={b.get('counts', {}).get('formerEmployees')}")
s, h, b, ms = viewer.req("GET", f"{V}/people?q=NM00001")
pid = b["items"][0]["id"] if s == 200 and b["items"] else None
s, h, b, ms = viewer.req("GET", f"{V}/people/{pid}")
user = next(u for u in [dict(zip(MANIFEST["users"]["columns"], r)) for r in MANIFEST["users"]["rows"]] if u.get("employeeId") == "NM00001") \
    if "employeeId" in MANIFEST["users"]["columns"] else None
check("representative person NM00001", s == 200 and (user is None or b.get("email") == user.get("email")
                                                      or b.get("person", {}).get("email") == user.get("email")),
      f"{s} {ms}ms {pid}")
group = manifest_group("sg-okta-crm-user")
ref = okta_ref(group["key"])
s, h, b, ms = viewer.req("GET", f"{V}/groups/{ref}")
check("representative group sg-okta-crm-user", s == 200, f"{s} {ms}ms {ref}")
s, h, b, ms = viewer.req("GET", f"{V}/mappings/{ref}")
check("correlation: mapping of sg-okta-crm-user present", s == 200, f"{s} {ms}ms confidence={b.get('confidence') if isinstance(b, dict) else '?'}")
s, h, b, ms = viewer.req("GET", f"{V}/applications?limit=200")
crm = next((a for a in b.get("items", []) if a.get("label") == "CRM" or "crm" in (a.get("label") or "").lower()), None) if s == 200 else None
s2, h2, b2, ms2 = viewer.req("GET", f"{V}/applications/{crm['id']}") if crm else (0, {}, {}, 0)
check("representative application (crm)", s2 == 200, f"{s2} {ms2}ms {crm and crm.get('label')}")
s, h, b, ms = viewer.req("GET", f"{V}/governance-findings?limit=1")
check("governance findings served", s == 200, f"{s} {ms}ms total={b.get('page', {}).get('total') if isinstance(b, dict) else '?'}")
s, h, b, ms = viewer.req("GET", f"{V}/candidates")
check("candidates == dataset CANDIDATES", s == 200 and len(b["items"]) == len(CANDIDATES), f"{s} {ms}ms {len(b.get('items', []))}")
s, h, b, ms = viewer.req("GET", f"{V}/demo-scenarios")
check("portfolio scenarios served", s == 200 and b["items"], f"{s} {ms}ms")
# The reviewer walkthrough, its two candidates resolved.
guide = b.get("walkthrough") or {} if isinstance(b, dict) else {}
check("reviewer walkthrough: NM-C10 then NM-C11, with its disclosures",
      [p.get("candidateKey") for p in guide.get("parts", [])] == ["NM-C10", "NM-C11"]
      and all(p.get("candidateId") for p in guide.get("parts", [])) and len(guide.get("disclosures", [])) == 4,
      f"{s} {ms}ms")
if not LOCAL:
    check("public walkthrough: no sign-in step, no synthetic principal named; NM-C11 is the visitor's drill",
          not any(x in json.dumps(guide) for x in ("synthetic.executor", "synthetic.securityiam", "Sign in", "Signed in"))
          and [p.get("candidateId") for p in guide.get("parts", []) if p.get("publicDrill")] == who["publicDrillCandidates"],
          f"{s} {ms}ms")
s, h, b, ms = viewer.req("GET", f"{V}/directory-groups?q=warehouse")
check("directory groups search", s == 200 and b["items"], f"{s} {ms}ms")
# A SID resolves to the group's common name and its canonical page, by stable id.
s, h, b, ms = viewer.req("GET", f"{V}/directory-groups?q=all-staff")
staff = viewer.req("GET", f"{V}/directory-groups/{b['items'][0]['id']}")[2]["group"] if s == 200 and b["items"] else {}
s, h, b, ms = viewer.req("GET", f"{V}/identities?ids={staff.get('adSid')},{staff.get('adEvidenceId')}")
entries = list(b.get("items", {}).values()) if s == 200 else []
check("identity: SID and AD evidence id resolve to All-Staff's page",
      len(entries) == 2 and all(e.get("name") == "All-Staff" and e.get("routeId") == staff.get("id") for e in entries),
      f"{s} {ms}ms")
s, h, b, ms = viewer.req("GET", f"{V}/people?sort=displayName&limit=50")
s2, h2, b2, ms2 = viewer.req("GET", f"{V}/people?sort=displayName&limit=50&cursor={b['page']['nextCursor']}") if s == 200 else (0, {}, {}, 0)
names = [p["displayName"].casefold() for p in b.get("items", []) + b2.get("items", [])]
check("people sorted across pages, counted", s2 == 200 and names == sorted(names) and b["page"]["total"] == 2809,
      f"{s} {ms}ms + {ms2}ms")
s, h, b, ms = viewer.req("GET", f"{V}/dashboard")
check("dashboard dependency summary", s == 200 and b.get("dependencyFindings", {}).get("blocking") == 4, f"{s} {ms}ms")

s, h, b, ms = viewer.req("GET", f"{V}/dashboard")
head = (b["store"]["auditEvents"], b["store"]["auditHead"]) if s == 200 else None
check("dashboard audit count and head are the seed's", s == 200 and head == (
    1458, "sha256:e8793f89dbff9c124d9c3b00fe0ea81d2ab5f07c1dc9bb05c8fce128d682eb41"), f"{s} {ms}ms {head}")
s, h, b, ms = viewer.req("GET", f"{V}/policy")
check("policy in force is NM-LIFECYCLE-004 v1.2.0, recorded version 2",
      s == 200 and b["inForce"].get("name") == "NM-LIFECYCLE-004 v1.2.0" and b["inForce"].get("versionSequence") == 1
      and [v["release"]["version"] for v in b["versions"]] == ["1.1.0", "1.2.0"], f"{s} {ms}ms")
cid = next(c["id"] for c in viewer.req("GET", f"{V}/candidates")[2]["items"] if c["state"] == "NEEDS_REVIEW")
if not LOCAL:  # a local demo records these; the hosted one refuses them
    for path, body in ((f"/candidates/{cid}/approvals", {"stage": "OKTA_UNASSIGN", "decision": "APPROVE", "reason": "x",
                                                           "validHours": 24, "acknowledged": True}),
                       (f"/candidates/{cid}/transitions", {"to": "BLOCKED", "reason": "x"}),
                       (f"/candidates/{cid}/transitions", {"to": "HOLD", "reason": "x"}),
                       (f"/mappings/{ref}/approvals", {"objectGuid": "x", "expectedEvidenceFingerprint": "x",
                                                       "reason": "x"}),
                       (f"/candidates/{cid}/execution-jobs", {"kind": "OKTA_UNASSIGN", "dryRun": True}),
                       (f"/candidates/{cid}/remediation-dry-runs", {"operation": "x"})):
        s, h, b, ms = viewer.req("POST", V + path, body)
        check(f"read-only refusal {path.split('/')[-1]} {body.get('to', '')}", s == 403
              and b["error"]["code"] == "DEMO_READ_ONLY"
              and b["error"]["message"].startswith("This public demo is read-only"), f"{s} {ms}ms")
# The hosted visitor drills NM-C11 itself; a local demo signs in as the executor.
ex = viewer
if LOCAL:
    ex = Client()
    ex.sign_in("synthetic.executor.one")
s, h, b, ms = ex.req("POST", f"{V}/execution-jobs/job_{'0' * 32}/execute", {})
check("execute refused", s == 403 and (LOCAL or b["error"]["code"] == "DEMO_MODE_BLOCKED"),
      f"{s} {b['error']['code'] if isinstance(b, dict) else b}")
# NM-C11's synthetic drill records nothing, even on the read-only store (the audit-head check
# below covers it).
c11 = next(c for c in viewer.req("GET", f"{V}/candidates")[2]["items"] if c["state"] == "APPROVED")
if not LOCAL:
    check("the visitor's one drill candidate is NM-C11", who["publicDrillCandidates"] == [c11["id"]], c11["id"])
detail = ex.req("GET", f"{V}/candidates/{c11['id']}")[2]
approval = ex.req("GET", f"{V}/candidates/{c11['id']}/approvals")[2]["items"][0]["id"]
s, h, b, ms = ex.req("POST", f"{V}/candidates/{c11['id']}/remediation-drills", {
    "operation": "OKTA_GROUP_UNASSIGN", "target": {"assignmentId": detail["candidate"]["assignmentIds"][0]},
    "approvalId": approval, "expectedEvidenceFingerprint": detail["evidenceFingerprint"],
    "mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED"})
drill = b.get("drill", {}) if isinstance(b, dict) else {}
check("synthetic drill: timeout, verify, one retry, verified; recorded nothing",
      s == 200 and drill.get("finalState") == "POST_ACTION_VERIFIED" and drill.get("submissions") == 2
      and drill.get("provider", {}).get("mutationsApplied") == 1 and drill.get("recorded") is False,
      f"{s} {ms}ms {drill.get('finalState')}")
chain, auth = (b.get("chain", {}), b.get("authorization", {})) if isinstance(b, dict) else ({}, {})
check("drill chain: NM-LIFECYCLE-004 v1.2.0, decision and approval judged by it; SYNTHETIC EXECUTION banner",
      (chain.get("policyId"), chain.get("policyVersion"), chain.get("postActionVerification")) ==
      ("NM-LIFECYCLE-004", "1.2.0", "CONFIRMED") and chain.get("operationId") == drill.get("operationId")
      and auth.get("authorized") is True
      and [auth.get(k, {}).get("binding") for k in ("decision", "approval")] == ["IN_FORCE", "IN_FORCE"]
      and drill.get("modeBanner", {}).get("headline") == "SYNTHETIC EXECUTION", f"{s} {ms}ms")
# Verification before the retry, one operation id, and the dry-run boundary.
ledger = drill.get("provider", {}).get("ledger", [])
check("drill order: unknown, verified not applied, retry with the same operation id, post-action verified",
      [st.get("state") for st in drill.get("steps", [])] == [
          "EXECUTION_REQUESTED", "OUTCOME_UNKNOWN", "VERIFYING", "RETRY_PERMITTED", "EXECUTION_REQUESTED", "EXECUTED",
          "POST_ACTION_VERIFIED"]
      and [e.get("actor") for e in ledger] == [drill.get("operationId")] * 2
      and [e.get("applied") for e in ledger] == [False, True], f"{len(ledger)} submissions")
s, h, b, ms = ex.req("POST", f"{V}/candidates/{c11['id']}/remediation-drills", {
    "operation": "OKTA_GROUP_UNASSIGN", "target": {"assignmentId": detail["candidate"]["assignmentIds"][0]},
    "approvalId": approval, "expectedEvidenceFingerprint": detail["evidenceFingerprint"], "mode": "DRY_RUN"})
dry = b.get("drill", {}) if isinstance(b, dict) else {}
check("dry run: DRY RUN — NO STATE CHANGED, nothing submitted, fixture unchanged, recorded nothing",
      s == 200 and dry.get("modeBanner", {}).get("headline") == "DRY RUN — NO STATE CHANGED"
      and (dry.get("finalState"), dry.get("submissions"), dry.get("recorded")) == ("DRY_RUN", 0, False)
      and dry.get("provider", {}).get("mutationsApplied") == 0 and dry.get("provider", {}).get("stateChanged") is False,
      f"{s} {ms}ms {dry.get('finalState')}")
c10 = next((p["candidateId"] for p in guide.get("parts", []) if p.get("candidateKey") == "NM-C10"), None)
d10 = ex.req("GET", f"{V}/candidates/{c10}")[2] if c10 else {}
verdict, why = d10.get("evidenceAssessment", {}).get("decision", {}), d10.get("decisionExplanation", {})
s10, _, b10, _ = ex.req("GET", f"{V}/candidates/{c10}/approvals") if c10 else (0, {}, {}, 0)
check("NM-C10: conflicting evidence, identity not established, not proven, not actionable, no approval",
      (verdict.get("code"), verdict.get("autoRemediationEligible"), verdict.get("eligibleForHumanApproval"))
      == ("CONFLICTING_EVIDENCE", False, False)
      and d10["evidenceAssessment"]["identity"].get("decisionGrade") is False
      and why.get("policy", {}).get("name") == "NM-LIFECYCLE-004 v1.2.0"
      and why.get("conditionCounts", {}).get("NOT_PROVEN", 0) > 0
      and s10 == 200 and b10.get("items") == [], f"{verdict.get('code')}")
for approval_id in (approval, "apr_" + "0" * 32):  # borrowed from NM-C11, and forged
    for mode in ({"mode": "DRY_RUN"}, {"mode": "SYNTHETIC_EXECUTION", "scenario": "TIMEOUT_NOT_APPLIED"}):
        s, h, b, ms = ex.req("POST", f"{V}/candidates/{c10}/remediation-drills", {
            "operation": "OKTA_GROUP_UNASSIGN", "target": {"assignmentId": d10["candidate"]["assignmentIds"][0]},
            "approvalId": approval_id, "expectedEvidenceFingerprint": d10["evidenceFingerprint"], **mode})
        # Hosted: outside the visitor's drill scope. Local: the shared approval-ownership check (404).
        check(f"NM-C10 drill refused ({'borrowed' if approval_id == approval else 'forged'}, {mode['mode']})",
              s == (404 if LOCAL else 403) and (LOCAL or b["error"]["code"] == "PUBLIC_DRILL_SCOPE")
              and "drill" not in b, f"{s} {ms}ms {b['error']['code'] if isinstance(b, dict) else b}")
s, h, b, ms = viewer.req("GET", f"{V}/session")
check("after the drills the visitor is still a viewer", (b["principal"]["roles"], b["principal"]["permissions"])
      == (["VIEWER"], ["READ_INVENTORY"]), f"{b['principal']['roles']}")
if LOCAL:
    auto = Client()
    auto.sign_in("synthetic.automation.one")
    s, h, b, ms = auto.req("POST", f"{V}/mappings/{ref}/inspection", {})
    check("live correlation inspection runs",
          s == 200 and b["confidence"] == EXPECTED_CONFIDENCE.get(group.get("correlationCase"), b["confidence"]),
          f"{s} {ms}ms confidence={b.get('confidence') if isinstance(b, dict) else '?'}")
else:
    s, h, b, ms = viewer.req("POST", f"{V}/mappings/{ref}/inspection", {})
    check("mapping inspection needs a mapping role no visitor has (403)", s == 403 and b["error"]["code"] == "FORBIDDEN",
          f"{s}")
s, h, b, ms = viewer.req("POST", f"{V}/session", {"subject": "synthetic.viewer.one"}, origin="https://evil.example")
check("cross-origin POST refused", s == 403 and b["error"]["code"] == "ORIGIN_REFUSED", f"{s}")
for path in ("/api/v1/bootstrap", "/api/v1/reset", "/api/v1/demo/reset", "/api/v1/runtime/reset-demo", "/admin", "/api/v1/system/reset"):
    s, h, b, ms = anon.req("POST", ORIGIN + path, {})
    check(f"no bootstrap/reset endpoint {path}", s in (404, 405), f"{s}")
if LOCAL:  # a writable demo chains each refused governed request into its audit log, and nothing else
    sec = Client()
    sec.sign_in("synthetic.securityiam.one")
    s, h, b, ms = sec.req("GET", f"{V}/audit-events?limit=50")
    after = [e for e in b.get("items", []) if e["sequence"] >= head[0]] if s == 200 else None  # head[0]: the count
    check("audit chain extended only by refusals", after is not None and len(after) < 50
          and all(e["action"] == "GOVERNED_REQUEST_REFUSED" for e in after), f"{len(after or [])} refusals")
else:
    fresh = Client()
    fresh.visit()
    s, h, b, ms = fresh.req("GET", f"{V}/dashboard")
    check("audit count and head unchanged after every attempt (a new visitor's view)",
          s == 200 and (b["store"]["auditEvents"], b["store"]["auditHead"]) == head, f"{head}")
failed = [r for r in RESULTS if not r[1]]
print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} smoke checks passed")
sys.exit(1 if failed else 0)
