"""The Review queue's rows and the approvals' usability (OGWA-REVIEW-QUEUE-API-01).

Both are readings for an operator, never decisions:

- A queue row is the candidate as recorded, its review status (``readmodel.REVIEW_STATUS``), and
  the **current evidence verdict**: what the classifier and the evidence assessment say about the
  evidence now, exactly as the candidate page computes them (``classify_and_assess``). The verdict
  is reported beside the recorded lifecycle state and compared with it; it is never written back,
  and it authorizes nothing (``isApproval: false``, ``autoRemediationEligible: false``).
- An approval's usability applies the lifecycle's own approval rules (``stage_approval_rules`` and
  ``approval_problems``, through ``LifecycleService.stage_approval_problems``, the call a dry run's
  planning makes) to the record as it stands, plus the remediation's policy binding. Usable means
  the approval would pass those checks now; the server checks everything again when it is used.
"""

from datetime import datetime
from typing import Any

from app.api.authorization import ACCEPTED_BINDINGS, BINDING_TEXT, binding
from app.api.readmodel import candidate_json, review_status
from app.api.errors import ApiError
from app.api.services import JOB_FROM_STATE, JOB_STAGE, JOB_TO_STATE, PolicyInForce, policy_in_force
from app.classification.classifier import LIFECYCLE_DIVERSIONS
from app.domain.approval import LEGACY_APPROVAL_STAGES, ApprovalDecision, ApprovalRecord
from app.domain.lifecycle import LifecycleCandidate, LifecycleState
from app.domain.policy import evidence_fingerprint
from app.domain.policy_release import PolicyRef

S = LifecycleState

# --- the current evidence verdict ------------------------------------------------------------

# Nothing further is decided in a terminal state, so a verdict there is not compared.
TERMINAL_STATES = frozenset({S.RETIRED, S.EXCLUDED, S.REJECTED, S.PROTECTED})
# States that record an evidence condition the classifier can suggest (its diversions).
EVIDENCE_STATES = frozenset(s for s in LIFECYCLE_DIVERSIONS.values() if s is not None) - TERMINAL_STATES

AGREES, DIFFERS, NOT_APPLICABLE, UNAVAILABLE = "AGREES", "DIFFERS", "NOT_APPLICABLE", "UNAVAILABLE"


def agreement(state: LifecycleState, classification: dict[str, Any] | None) -> str:
    """How the classifier's current suggestion stands against the recorded state. ``DIFFERS`` when it
    would park the candidate elsewhere, or no longer finds the evidence condition the state records.
    Either way the recorded state stands until the lifecycle records a transition."""
    if state in TERMINAL_STATES:
        return NOT_APPLICABLE
    if classification is None:
        return UNAVAILABLE
    suggested = classification["lifecycleDiversion"]
    if suggested is not None:
        return AGREES if suggested == state.value else DIFFERS
    return DIFFERS if state in EVIDENCE_STATES else AGREES


def evidence_verdict(state: LifecycleState, classification: dict[str, Any] | None,
                     assessment: dict[str, Any]) -> dict[str, Any]:
    """The listing-sized verdict: no reasons' detail, evidence items, or explanation (those are on
    the candidate page, ``GET /candidates/{id}``)."""
    decision = assessment["decision"]
    blocking = [] if classification is None else list(dict.fromkeys(
        r["code"] for r in classification["reasons"] if r["blocks"]))
    return {
        "classification": classification["classification"] if classification else None,
        "suggestedState": classification["lifecycleDiversion"] if classification else None,
        "decision": {"code": decision["code"], "label": decision["label"],
                     "eligibleForHumanApproval": decision["eligibleForHumanApproval"]},
        "agreement": agreement(state, classification),
        "blockingReasons": blocking,
        "assessedAt": assessment["assessedAt"],
        "isApproval": False,
        "autoRemediationEligible": False,
    }


def queue_item(api, candidate: LifecycleCandidate) -> dict[str, Any]:
    """One queue row: the candidate as recorded, its review status, and the current evidence verdict."""
    classification, assessment = api.lifecycle.classify_and_assess(candidate, api.store.evidence_bundle(candidate))
    return {**candidate_json(candidate), "reviewStatus": review_status(candidate.state.value),
            "evidenceVerdict": evidence_verdict(candidate.state, classification, assessment)}


# --- approval usability ------------------------------------------------------------------------

# Where each stage's approval is used: its approved state (a dry run is planned there) and the
# dry-run state that cites it (app/domain/lifecycle.py; app/api/services.py JOB_* tables).
USED_IN = {stage: frozenset({JOB_FROM_STATE[kind], JOB_TO_STATE[kind]}) for kind, stage in JOB_STAGE.items()}

USABLE = "USABLE"
NOT_AN_APPROVAL = "NOT_AN_APPROVAL"  # a rejection
LEGACY = "LEGACY"  # AD_RETIREMENT (D148): history only
EXPIRED = "EXPIRED"
EPOCH_SUPERSEDED = "EPOCH_SUPERSEDED"  # the candidate was blocked and re-entered review since
STAGE_NOT_CURRENT = "STAGE_NOT_CURRENT"  # the candidate is not (or no longer) where this approval is used
EVIDENCE_CHANGED = "EVIDENCE_CHANGED"  # the material evidence's fingerprint changed since
POLICY_NOT_IN_FORCE = "POLICY_NOT_IN_FORCE"  # judged by a policy other than the version in force
NO_POLICY = "NO_POLICY"  # no candidate policy is in force (D52), so nothing can be judged
NOT_USABLE = "NOT_USABLE"  # any other rule the lifecycle applies


class ApprovalUsability:
    """``usability`` for the approvals of one response, at one instant and under one policy. Each
    candidate (and, only when everything else passes, its evidence fingerprint) is read once."""

    def __init__(self, api, now: datetime) -> None:
        self._api, self._now = api, now
        self._candidates: dict[str, LifecycleCandidate] = {}
        self._fingerprints: dict[str, str] = {}
        try:
            self._policy: PolicyInForce | None = policy_in_force(api.store)
        except ApiError:  # no policy in force: every approval is reported unusable
            self._policy = None

    def _candidate(self, cid: str) -> LifecycleCandidate:
        if cid not in self._candidates:
            self._candidates[cid] = self._api.store.load_candidate(cid)
        return self._candidates[cid]

    def _fingerprint(self, c: LifecycleCandidate) -> str:
        if c.id not in self._fingerprints:
            self._fingerprints[c.id] = evidence_fingerprint(self._api.store.evidence_bundle(c))
        return self._fingerprints[c.id]

    def of(self, a: ApprovalRecord, recorded: PolicyRef | None) -> dict[str, Any]:
        if a.decision is not ApprovalDecision.APPROVE:
            return {"status": NOT_AN_APPROVAL, "usable": False, "problems": ["a rejection authorizes nothing"]}
        if a.stage in LEGACY_APPROVAL_STAGES:
            return {"status": LEGACY, "usable": False, "problems": ["a legacy AD_RETIREMENT approval authorizes "
                                                                    "nothing (D148)"]}
        c = self._candidate(a.candidate_id)
        if self._policy is None:
            return {"status": NO_POLICY, "usable": False,
                    "problems": ["no candidate policy is in force, so no approval can be judged (D52)"]}
        problems = []
        if c.state not in USED_IN[a.stage]:
            problems.append(f"the candidate is {c.state.value}; an approval of {a.stage.value} is used only in "
                            f"{' or '.join(sorted(s.value for s in USED_IN[a.stage]))}")
        # The evidence check needs the candidate's evidence read: only when nothing else already fails.
        problems += self._api.lifecycle.stage_approval_problems(c, a, a.stage, self._policy, self._now, None)
        bound = binding(recorded, self._policy.ref)
        if bound not in ACCEPTED_BINDINGS:
            problems.append(f"{BINDING_TEXT[bound]} Remediation dry runs and drills refuse it (OGWA-DEMO-04).")
        if not problems:
            problems = self._api.lifecycle.stage_approval_problems(c, a, a.stage, self._policy, self._now,
                                                                   self._fingerprint(c))
        return {"status": self._status(a, c, problems, bound), "usable": not problems, "problems": problems}

    def _status(self, a: ApprovalRecord, c: LifecycleCandidate, problems: list[str], bound) -> str:
        """The headline, most telling first; ``problems`` (the rules' own words) is the whole answer."""
        if not problems:
            return USABLE
        if self._now >= a.expires_at:
            return EXPIRED
        if a.candidate_epoch != c.epoch:
            return EPOCH_SUPERSEDED
        if c.state not in USED_IN[a.stage]:
            return STAGE_NOT_CURRENT
        if bound not in ACCEPTED_BINDINGS:
            return POLICY_NOT_IN_FORCE
        if a.evidence_fingerprint != self._fingerprint(c):
            return EVIDENCE_CHANGED
        return NOT_USABLE
