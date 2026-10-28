"""The reviewer walkthrough of the Null Meridian demo (OGWA-DEMO-04): about five minutes.

Two parts, two candidates, each showing what the other cannot:

1. **Data quality** (NM-C10): conflicting and incomplete evidence, an identity mapping that is
   not proven, conditions that are *not proven* rather than failed, and no remediation at all.
2. **Controlled remediation** (NM-C11): fresh evidence, a decision and an approval recorded
   under NM-LIFECYCLE-004 v1.2.0, a dry run that changes nothing, then a deterministic
   synthetic execution: timeout, verification, one safe retry, post-action verification.

This is text and candidate keys only. Every page it points to is the application's own, and
every state it describes is computed by the server (the evidence assessment, the decision
explanation, the governed gates, the drill); nothing here judges or records anything. The API
resolves each candidate key to its candidate id from the directory snapshot's scenarios.
"""

from typing import Any

TITLE = "Reviewer walkthrough (about five minutes)"
SUMMARY = ("Two synthetic candidates, two lessons: when the evidence is not good enough, OGWA refuses to act and says "
           "why; when it is, an action is a controlled, verified state transition, never a button click.")

# What a reviewer must know before starting. Shown above both parts.
DISCLOSURES = (
    "All data is synthetic: Null Meridian is a fictional company, and every person, group, application, policy, "
    "approval, and audit event here was generated.",
    "No external provider is contacted: no Okta tenant, Active Directory, AAP, or HR system is reached, and no "
    "credential exists in this demo.",
    "The synthetic execution drill runs against an in-memory provider fixture built from the candidate's recorded "
    "synthetic evidence and discarded after each answer. Nothing it does is recorded, and the candidate's lifecycle "
    "state does not change.",
    "Failure injection is deterministic: each fault scenario is a fixed script on a synthetic clock, so the same "
    "scenario always gives the same timeout, verification read, and retry.",
)

PARTS: tuple[dict[str, Any], ...] = (
    {
        "key": "data-quality",
        "title": "Part 1 — Data quality: incomplete and conflicting evidence",
        "candidateKey": "NM-C10",
        "outcome": "Manual review. No approval can be recorded and no dry run or drill can start.",
        "steps": (
            {"text": "Open NM-C10 (KB-Admins) from the link above.", "section": None},
            {"text": "Read the decision at the top: \"No action: sources disagree\" (CONFLICTING_EVIDENCE). OGWA "
                     "will not treat this candidate as safe to act on.", "section": "Is this safe to act on?"},
            {"text": "Under question 3, find the conflict (the AD group object lists 2 members, the membership read "
                     "found none), the failed nesting read (Source unavailable), the stopped ACL scan (Partial), and "
                     "the checks never run (Not collected). Missing evidence is never shown as \"none\".",
             "section": "Is this safe to act on?"},
            {"text": "Under question 4, the identity mapping is \"Probable, not proven\" (an unverified directory "
                     "SID), not confirmed.", "section": "Is this safe to act on?"},
            {"text": "Open \"Why this decision\": it names NM-LIFECYCLE-004 v1.2.0, the exact version in force, "
                     "with its rules digest.", "section": "Why this decision"},
            {"text": "In the conditions table, the exact mapping and the AD conditions are Not proven (or not "
                     "judged), never Satisfied and never Not satisfied: the evidence cannot say either way.",
             "section": "Why this decision"},
            {"text": "\"Did ambiguous or missing evidence force manual review?\" is Yes, and \"What would need to "
                     "change for a different outcome\" lists the evidence needed: resolve the conflict, establish the "
                     "AD counterpart, collect the missing checks.", "section": "Why this decision"},
            {"text": "No remediation is offered: the candidate has no approval, and the lifecycle refuses one while "
                     "the mapping is not exact.", "section": None},
        ),
    },
    {
        "key": "controlled-remediation",
        "title": "Part 2 — Controlled remediation: dry run, failure, verification, safe retry",
        "candidateKey": "NM-C11",
        "publicDrill": True,  # the one candidate a public-demo visitor may drill (app.runtime.api)
        "outcome": "POST-ACTION VERIFIED, inside the synthetic fixture only, after one verified-safe retry.",
        "steps": (
            {"text": "Sign in as an executor (synthetic.executor.one) and open NM-C11 (OKTA-AdAnalytics-Users).",
             "public": "Open NM-C11 (OKTA-AdAnalytics-Users). No sign-in is needed: in this public demo, every "
                       "visitor may run this candidate's synthetic drill, and no other.",
             "section": None},
            {"text": "Its evidence was collected again on the snapshot day: the assessment shows current, "
                     "decision-grade evidence and an exact mapping.", "section": "Is this safe to act on?"},
            {"text": "\"Why this decision\" names NM-LIFECYCLE-004 v1.2.0. The decision history shows the triage "
                     "under v1.1.0 (superseded) and the snapshot-day approval and APPROVED decision under v1.2.0.",
             "section": "Why this decision"},
            {"text": "In \"Remediation: dry run or synthetic drill\", choose Dry run and run it. The banner says "
                     "DRY RUN — NO STATE CHANGED; the state digests before and after are identical and the ledger "
                     "is empty.", "section": "Remediation: dry run or synthetic drill"},
            {"text": "Choose Synthetic execution drill, the scenario \"Timeout, change not applied\", and run it. The "
                     "result is marked SYNTHETIC EXECUTION: no external provider or persistent environment was "
                     "modified.", "section": "Remediation: dry run or synthetic drill"},
            {"text": "Follow the steps: the first submission times out (OUTCOME UNKNOWN — VERIFYING); a read shows "
                     "the change was not applied; only then RETRY PERMITTED; the retry, with the same operation id, "
                     "is applied; a post-action read confirms it: POST-ACTION VERIFIED.",
             "section": "Remediation: dry run or synthetic drill"},
            {"text": "Under \"Authorized by\", check the chain: the policy version, the decision and the approval "
                     "with their audit sequences, both judged by v1.2.0, and the operation id every attempt carried.",
             "section": "Remediation: dry run or synthetic drill"},
            {"text": "Reload the page: the candidate is still APPROVED. Signed in as a security reviewer "
                     "(synthetic.securityiam.one), its audit history shows no event from the drill: the drill "
                     "recorded nothing.",
             "public": "Reload the page: the candidate is still APPROVED, with the same decisions and approval, and "
                       "the dashboard's audit event count and head have not moved: the drill recorded nothing.",
             "section": None},
        ),
    },
)


def walkthrough(public: bool = False) -> dict[str, Any]:
    """The walkthrough as data, candidate keys unresolved. ``public``: worded for the public demo, which has no
    sign-in and names no synthetic principal."""
    def step(s: dict[str, Any], n: int) -> dict[str, Any]:
        return {"text": s.get("public", s["text"]) if public else s["text"], "section": s["section"], "n": n}

    return {"title": TITLE, "summary": SUMMARY, "disclosures": list(DISCLOSURES),
            "parts": [{**p, "steps": [step(s, i) for i, s in enumerate(p["steps"], start=1)]} for p in PARTS]}


__all__ = ["DISCLOSURES", "PARTS", "SUMMARY", "TITLE", "walkthrough"]
