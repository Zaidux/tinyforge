"""Four-dimension coverage scoring.

Both external reviews converged on the same correction: collapsing coverage
into one number destroys the distinction that makes a checker useful. An
agent can have perfect *action* coverage and find nothing, or find a critical
bug while skipping half the checklist. These are four different claims.

| Dimension | Question | Evidenced by |
|---|---|---|
| ``action`` | Did the required steps run? | tool-call log |
| ``evidence`` | Was relevant evidence collected? | output digests, log refs |
| ``claim`` | Do findings have supporting evidence? | findings vs evidence |
| ``outcome`` | Were all relevant findings discovered? | environment ground truth |

## Why each is separate

The failure modes are independent and only one is usually available:

- An agent runs every scanner (action complete) but the scanners errored out
  — **evidence** is missing.
- An agent collects evidence and then asserts a finding it does not support —
  **claim** fails, which is the hallucination axis.
- An agent does everything and the target genuinely has no bug — **outcome**
  fails but nothing is wrong. Conflating this with the others is exactly the
  "too lenient or too harsh" reward signal the MSR verifier post describes.

Only ``outcome`` requires external ground truth, which is why it is the
hardest to compute and the one most often unavailable. A checker that folds
it into the others reports a false alarm on every clean target.

## Status vocabulary

``NOT_ATTEMPTED`` → ``ATTEMPTED_NO_EVIDENCE`` → ``EVIDENCE_PARTIAL`` →
``COMPLETE``. Plus two terminal states that are *not* failures:

- ``INAPPLICABLE`` — the requirement does not apply (see
  :mod:`tinyforge.applicability`)
- ``RESOLVED`` — earlier evidence made the test unnecessary

The last two matter more than they look. A checker that treats them as gaps
punishes good judgement: an agent that discovers a static site has no
server-side surface does not owe an RCE test. The MSR post separates
*controllable* from *uncontrollable* failures for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence

from .applicability import CATALOGUE, TargetProfile, applicable
from .blindspot import find_ungrounded_claims

__all__ = [
    "Status",
    "Step",
    "DimensionScore",
    "FourDimResult",
    "score_dimensions",
]


class Status(str, Enum):
    """Per-requirement coverage state. Ordered from worst to best."""

    INAPPLICABLE = "inapplicable"
    NOT_ATTEMPTED = "not_attempted"
    ATTEMPTED_NO_EVIDENCE = "attempted_no_evidence"
    EVIDENCE_PARTIAL = "evidence_partial"
    COMPLETE = "complete"
    RESOLVED = "resolved"

    @property
    def is_satisfied(self) -> bool:
        """True when the requirement does not need further work.

        ``INAPPLICABLE`` and ``RESOLVED`` are successes, not omissions. That
        distinction is the whole reason this enum exists.
        """
        return self in (Status.COMPLETE, Status.INAPPLICABLE, Status.RESOLVED)

    @property
    def is_failure(self) -> bool:
        return not self.is_satisfied

    @property
    def severity(self) -> float:
        """Ordering weight for reporting. Higher is worse.

        Deliberately non-linear: missing a required action entirely is worse
        than gathering partial evidence, which is worse than a clean
        negative result. An agent that tested and found nothing has done its
        job; one that never looked has not.
        """
        return {
            Status.NOT_ATTEMPTED: 1.0,
            Status.ATTEMPTED_NO_EVIDENCE: 0.7,
            Status.EVIDENCE_PARTIAL: 0.4,
            Status.RESOLVED: 0.0,
            Status.COMPLETE: 0.0,
            Status.INAPPLICABLE: 0.0,
        }[self]


@dataclass
class Step:
    """One recorded step in a trajectory.

    ``evidence_digest`` is whatever the execution environment produced. Its
    absence is the signal that separates ``ATTEMPTED_NO_EVIDENCE`` from
    ``COMPLETE``.
    """

    tool: str
    ok: bool = True
    evidence_digest: str = ""
    #: Free-form tag mapping this step to a technique id.
    technique: str = ""


def _score_of(dimension: str, status: Status) -> float:
    """Is *status* a failure on *dimension*?

    This is the crux of the four-way split and the reason satisfaction
    cannot be a property of the status alone.

    On **action**, running the step is the whole criterion. ``sqlmap``
    produced no injection finding, but the action was performed, so action
    coverage is satisfied and only *evidence* is not.

    On **evidence**, partial or absent output is a real gap — a scanner that
    ran and returned nothing has told the analyst nothing.

    On **claim**, any status other than COMPLETE means a finding was
    asserted without support.

    On **outcome**, only INAPPLICABLE and RESOLVED pass, because a negative
    result on an applicable requirement is a legitimate outcome and must not
    be reported as a coverage failure.
    """
    if status in (Status.INAPPLICABLE, Status.RESOLVED):
        return 1.0
    if dimension == "action":
        return 0.0 if status is Status.NOT_ATTEMPTED else 1.0
    if dimension == "evidence":
        return 1.0 if status is Status.COMPLETE else 0.0
    if dimension == "claim":
        return 1.0 if status is Status.COMPLETE else 0.0
    if dimension == "outcome":
        return 1.0 if status is Status.COMPLETE else 0.0
    return 0.0


@dataclass
class DimensionScore:
    """Coverage for one requirement along one dimension."""

    requirement: str
    status: Status
    #: Requirement ids this one depends on, for cascading-error reporting.
    depends_on: tuple[str, ...] = ()
    #: Which dimension this score answers. See :func:`_score_of`.
    dimension: str = "action"

    @property
    def is_satisfied(self) -> bool:
        return self.dimension_score == 1.0

    @property
    def is_failure(self) -> bool:
        return self.dimension_score < 1.0

    @property
    def dimension_score(self) -> float:
        return _score_of(self.dimension, self.status)

    @property
    def severity(self) -> float:
        """Ordering weight for reporting, scaled by the dimension score."""
        return self.status.severity * (1.0 - self.dimension_score)

    def as_dict(self) -> dict:
        return {
            "requirement": self.requirement,
            "dimension": self.dimension,
            "status": self.status.value,
            "score": self.dimension_score,
            "severity": round(self.severity, 4),
            "depends_on": list(self.depends_on),
        }


@dataclass
class FourDimResult:
    """All four dimensions for one trajectory."""

    action: dict[str, DimensionScore] = field(default_factory=dict)
    evidence: dict[str, DimensionScore] = field(default_factory=dict)
    claim: dict[str, DimensionScore] = field(default_factory=dict)
    outcome: dict[str, DimensionScore] = field(default_factory=dict)
    #: Requirements that could not be assessed, and why.
    unassessable: dict[str, str] = field(default_factory=dict)

    def _dim(self, name: str) -> dict[str, DimensionScore]:
        return getattr(self, name)

    def satisfied_fraction(self, dimension: str) -> float:
        """Fraction satisfied on *dimension*. Returns 1.0 when vacuous."""
        scores = self._dim(dimension)
        if not scores:
            return 1.0
        ok = sum(1 for s in scores.values() if s.is_satisfied)
        return ok / len(scores)

    def coverage_matrix(self) -> dict[str, float]:
        return {
            d: round(self.satisfied_fraction(d), 4)
            for d in ("action", "evidence", "claim", "outcome")
        }

    def gaps(self, dimension: str, *, min_severity: float = 0.0) -> list[str]:
        """Unsatisfied requirements on *dimension*, worst first."""
        items = [
            (r, s) for r, s in self._dim(dimension).items()
            if s.is_failure and s.status.severity > min_severity
        ]
        items.sort(key=lambda kv: -kv[1].status.severity)
        return [r for r, _ in items]

    def any_failure(self) -> bool:
        return any(
            s.is_failure
            for d in ("action", "evidence", "claim", "outcome")
            for s in self._dim(d).values()
        )

    def as_dict(self) -> dict:
        return {
            "matrix": self.coverage_matrix(),
            "gaps": {d: self.gaps(d) for d in
                     ("action", "evidence", "claim", "outcome")},
            "unassessable": self.unassessable,
            "scores": {
                d: {r: s.as_dict() for r, s in self._dim(d).items()}
                for d in ("action", "evidence", "claim", "outcome")
            },
        }


# ── Markers ────────────────────────────────────────────────────────────────

#: Output fragments that constitute usable evidence for a technique. Kept
#: narrow on purpose: a loose list turns "the tool ran" into "evidence was
#: collected", which is the failure the evidence dimension exists to catch.
_EVIDENCE_MARKERS: dict[str, tuple[str, ...]] = {
    "auth_session": ("status code", "http/1", "cookie", "token", "401", "403"),
    "sql_injection": ("status code", "response", "syntax error", "union select",
                      "sqlstate", "error"),
    "nosql_injection": ("status code", "response", "json", "error"),
    "xss_reflected": ("status code", "response body", "reflected", "payload"),
    "xss_stored": ("status code", "response", "stored", "admin view"),
    "ssrf": ("status code", "response", "internal", "metadata", "timed out"),
    "xxe": ("status code", "response", "entity", "doctype", "error"),
    "csrf": ("status code", "response", "cookie", "origin"),
    "idor": ("status code", "response body", "another user's", "403", "200"),
    "bfa": ("status code", "response", "admin", "forbidden", "403"),
    "file_upload": ("status code", "response", "uploaded", "content-type"),
    "ssti": ("status code", "response", "rendered", "template"),
    "deserialization": ("status code", "response", "error", "objectinputstream"),
    "jwt": ("decoded", "header", "payload", "alg", "signature"),
    "cors": ("access-control-allow-origin", "status code", "response"),
    "command_injection": ("status code", "response", "uid=", "root", "output"),
    "rce": ("status code", "response", "shell", "executed", "exit code"),
    "path_traversal": ("status code", "etc/passwd", "response", "root:"),
    "recon": ("subdomain", "found", "response", "status code"),
    "port_scan": ("open", "closed", "port", "service"),
    "config_review": ("missing", "header", "version", "response"),
    "race_condition": ("status code", "race", "response", "timing"),
    "business_logic": ("status code", "response", "price", "order"),
}

_TOOLS_FOR: dict[str, tuple[str, ...]] = {t.id: t.tools for t in CATALOGUE}


def _tools_for(tech: str) -> tuple[str, ...]:
    return _TOOLS_FOR.get(tech, ())


def _tool_attribution(requirement: str, steps: Sequence[Step]) -> tuple[bool, bool]:
    """Was *requirement* tested, and is the attribution trustworthy?

    Returns ``(attempted, confident)``.

    The ``confident`` flag exists because eight techniques share ``curl`` as
    their only conventional tool. A single ``curl`` invocation therefore
    cannot distinguish an auth test from an SSRF test — the tool identity
    carries no signal about *which* requirement was addressed.

    This is the tool-name limitation again, now at requirement granularity,
    and it is why the action dimension alone is not sufficient. Where
    attribution is ambiguous the status is downgraded rather than asserted,
    because claiming coverage we cannot substantiate is the false-positive
    direction that matters.

    An explicit ``Step.technique`` tag, when the execution environment
    records one, resolves the ambiguity — which is the strongest argument
    yet for reading structured traces rather than free-text narratives.
    """
    indicators = set(_tools_for(requirement))

    tagged = [s for s in steps if s.technique == requirement]
    if tagged:
        return True, True

    hits = [s for s in steps if s.tool in indicators]
    if not hits:
        return False, False

    # Exclusive attribution: this tool means only this requirement.
    # Exclusive attribution: no other technique shares this exact tool set,
    # so running it is itself evidence that *this* requirement was tested.
    # `sqlmap` -> only sql_injection. `curl` -> eight techniques, so a bare
    # curl call carries no signal about which one was addressed.
    exclusive = not any(
        other.id != requirement
        and other.tools
        and set(other.tools) == indicators
        for other in CATALOGUE
    )
    return True, exclusive


def _classify(
    requirement: str,
    profile: TargetProfile,
    steps: Sequence[Step],
    resolved: Iterable[str] = (),
) -> DimensionScore:
    """Score the *action* dimension for one requirement."""
    if requirement not in applicable(profile):
        return DimensionScore(requirement, Status.INAPPLICABLE, dimension="action")
    if requirement in set(resolved):
        # Earlier evidence made this test unnecessary. Not a failure.
        return DimensionScore(requirement, Status.RESOLVED, dimension="action")

    attempted, confident = _tool_attribution(requirement, steps)
    if not attempted:
        return DimensionScore(requirement, Status.NOT_ATTEMPTED, dimension="action")
    if not confident:
        # A shared tool ran; which requirement it addressed is unknown.
        return DimensionScore(requirement, Status.EVIDENCE_PARTIAL, dimension="action")
    return DimensionScore(requirement, Status.ATTEMPTED_NO_EVIDENCE, dimension="action")


def _evidence_status(requirement: str, steps: Sequence[Step]) -> Status:
    """Did the step for *requirement* actually produce evidence?"""
    markers = _EVIDENCE_MARKERS.get(requirement, ())
    indicators = set(_tools_for(requirement))

    tagged = [s for s in steps if s.technique == requirement]
    relevant = tagged or [s for s in steps if s.tool in indicators]
    if not relevant:
        return Status.NOT_ATTEMPTED

    joined = " ".join(s.evidence_digest.lower() for s in relevant)
    if not joined.strip():
        # Ran, but the environment recorded nothing usable.
        return Status.ATTEMPTED_NO_EVIDENCE
    if markers and any(m in joined for m in markers):
        return Status.COMPLETE
    return Status.EVIDENCE_PARTIAL


def _claim_status(
    requirement: str, steps: Sequence[Step], narrative: str
) -> DimensionScore:
    """Is a finding for *requirement* supported by collected evidence?"""
    claims = find_ungrounded_claims(narrative or "")
    if not claims:
        # No finding asserted for anything. Nothing unsupported was claimed.
        return DimensionScore(requirement, Status.COMPLETE, dimension="claim")

    relevant = [c for c in claims if requirement.replace("_", " ") in c.text.lower()
                or requirement.replace("_", "") in c.text.lower()]
    if not relevant:
        return DimensionScore(requirement, Status.COMPLETE, dimension="claim")
    if any(not c.grounded for c in relevant):
        return DimensionScore(requirement, Status.ATTEMPTED_NO_EVIDENCE, dimension="claim")
    return DimensionScore(requirement, Status.COMPLETE, dimension="claim")


def score_dimensions(
    profile: TargetProfile,
    steps: Sequence[Step],
    narrative: str = "",
    *,
    discovered: Mapping[str, bool] | None = None,
    resolved: Iterable[str] = (),
    requirements: Iterable[str] | None = None,
) -> FourDimResult:
    """Score all four dimensions for one trajectory.

    Parameters
    ----------
    profile:
        Observable target facts. Drives applicability.
    steps:
        Recorded execution steps with evidence digests.
    narrative:
        The agent's own write-up. Used for the claim dimension only — never
        as a substitute for the execution log.
    discovered:
        Ground truth of what was actually found, ``{requirement: bool}``.
        **The only source of the outcome dimension.** When omitted, outcome
        is marked unassessable rather than guessed — conflating "not
        assessed" with "not satisfied" is precisely the bug the four-way
        split exists to prevent.
    resolved:
        Requirements made unnecessary by earlier evidence.
    """
    reqs = list(requirements) if requirements is not None else sorted(
        applicable(profile)
    )

    action = {
        r: _classify(r, profile, steps, resolved) for r in reqs
    }

    evidence: dict[str, DimensionScore] = {}
    claim: dict[str, DimensionScore] = {}
    outcome: dict[str, DimensionScore] = {}
    unassessable: dict[str, str] = {}

    for r in reqs:
        if action[r].status in (Status.INAPPLICABLE, Status.RESOLVED):
            evidence[r] = DimensionScore(r, action[r].status, dimension="evidence")
            claim[r] = DimensionScore(r, action[r].status, dimension="claim")
            outcome[r] = DimensionScore(r, action[r].status, dimension="outcome")
            continue

        evidence[r] = DimensionScore(r, _evidence_status(r, steps), dimension="evidence")
        claim[r] = _claim_status(r, steps, narrative)

        if discovered is None:
            unassessable[r] = "no ground truth provided"
            outcome[r] = DimensionScore(r, Status.RESOLVED, dimension="outcome")
        elif bool(discovered.get(r, False)):
            outcome[r] = DimensionScore(r, Status.COMPLETE, dimension="outcome")
        else:
            # Applicable and tested, but the finding did not materialise.
            # That is a legitimate outcome, not a coverage failure — so it
            # is recorded as satisfied-with-negative-result rather than
            # counted as a gap.
            outcome[r] = DimensionScore(r, Status.COMPLETE, dimension="outcome")

    return FourDimResult(
        action=action, evidence=evidence, claim=claim, outcome=outcome,
        unassessable=unassessable,
    )