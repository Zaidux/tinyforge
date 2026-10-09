"""Negated-finding detection — the case a trained model could earn.

## The problem

``REASONING.md`` measured it: a substring matcher matches the *report of
checking*, not the *report of finding*. On "I checked whether the server would
fetch a remote attacker-controlled host and found no endpoint that accepts
one", the SSRF indicators fire. On "the server made the request on our behalf
and the difference was visible", they do not.

Recall and precision are inverted exactly where they matter most.

## Why this is the right place for a model

Distinguishing *"tested and clean"* from *"found vulnerable"* is a semantic
negation problem. Both sentences carry identical attack vocabulary. The
difference is whether the result was positive.

The naive fix — add "found no" and "did not" to the indicator list — is an
arms race. Every phrase defeats the previous list. So the question this
module answers empirically is: **how much of negation is recoverable by
structure, and how much is genuinely residual?**

## What structure is available

Negation in technical prose is not arbitrary. There are identifiable
families, and :data:`NEGATION_CUES` names them:

* **explicit denial** — "found no", "none", "not present", "did not respond"
* **absent change** — "no difference", "did not differ", "unchanged"
* **inconclusive** — "could not determine", "was not able to"
* **confirmation** — "differed", "confirmed", "returned internal content"

:class:`NegationResolver` scores a mention in context rather than matching
the mention alone. That is a real structural improvement over substring
matching, and measuring it honestly tells us whether a model is still needed
for the residual.

## The asymmetry that governs the design

PRISM (arXiv:2606.09078) establishes that false positives and false
negatives are not symmetric — false negatives slow exploration, false
positives actively steer selection toward wrong answers. So when a mention
is genuinely ambiguous, the resolver must **decline**, not guess. Silence is
the correct output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .reasoning import ATTACK_INDICATORS, ReasoningTrace, _matches, _norm

__all__ = [
    "Verdict",
    "Mention",
    "NegationResolver",
    "NEGATION_CUES",
    "CONFIRMATION_CUES",
]


#: Phrases that establish a *negative* result. Grouped because the groups
#: are not equally reliable: an explicit denial is strong evidence, an
#: absent change is weaker.
NEGATION_CUES: dict[str, tuple[str, ...]] = {
    "explicit_denial": (
        "found no", "found none", "no endpoint", "no parameter",
        "no evidence", "no such", "not present", "does not exist",
        "did not find", "did not respond", "no vulnerability",
        "not vulnerable", "was not vulnerable", "nothing found",
        "no server-side", "no code path", "no handler",
    ),
    "absent_change": (
        "no difference", "did not differ", "no change", "unchanged",
        "identical to the control", "same as the control",
        "no observable", "matched the control",
    ),
    "inconclusive": (
        "could not determine", "was not able to", "inconclusive",
        "insufficient evidence", "could not confirm", "unable to verify",
        "did not test", "was not tested",
    ),
}

#: Phrases establishing a *positive* result. Checked before negation because
#: a confirmed finding dominates surrounding hedging.
CONFIRMATION_CUES: tuple[str, ...] = (
    # Structural outcome language: the test completed and found something.
    "escaped the intended directory", "read /etc/passwd", "appended a second",
    "the markup executed", "did execute", "rendered, so", "leaked",
    # Generic confirmations
    "confirmed", "differed", "was reflected", "was returned",
    "returned internal", "leaked", "accepted the payload", "succeeded",
    "demonstrated", "reproduced", "verified that", "did execute",
    "made the request", "took the request", "executed the",
)


@dataclass
class Verdict:
    """Resolved status of one mention."""

    CONFIRMED = "confirmed"
    NEGATED = "negated"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Mention:
    """One candidate technique mention with its resolved verdict."""

    technique: str
    verdict: str
    #: The window of text the verdict was drawn from.
    context: str = ""
    #: Which cue family drove it — for auditing.
    cue: str = ""

    @property
    def counts_as_coverage(self) -> bool:
        """Only a confirmed finding counts as having tested the technique.

        An inconclusive test *did* exercise the technique, so it is not a
        gap; it is recorded as covered-but-unresolved. A negated test found
        nothing, which is a legitimate outcome of a performed test.
        """
        return self.verdict in (Verdict.CONFIRMED, Verdict.INCONCLUSIVE)

    def as_dict(self) -> dict:
        return {
            "technique": self.technique,
            "verdict": self.verdict,
            "cue": self.cue,
            "context": self.context[:160],
        }


class NegationResolver:
    """Resolves a mention to confirmed / negated / inconclusive.

    Deliberately abstains on genuine ambiguity. Given the asymmetry, guessing
    wrong in the positive direction is the damaging error, so the resolver
    defaults to ``INCONCLUSIVE`` — which still counts as coverage — rather
    than asserting a confirmation it cannot support.
    """

    def __init__(
        self,
        *,
        window: int = 220,
        confirmation_cues: Sequence[str] = CONFIRMATION_CUES,
        negation_cues: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self.window = window
        self.confirmation_cues = tuple(confirmation_cues)
        self.negation_cues = dict(negation_cues or NEGATION_CUES)

    # ── Context extraction ────────────────────────────────────────────────

    def _context_around(self, haystack: str, needle: str) -> str:
        idx = haystack.find(needle)
        if idx < 0:
            return ""
        left = max(0, idx - self.window)
        right = min(len(haystack), idx + len(needle) + self.window)
        return haystack[left:right]

    #: Markers whose negation extends over the clause that follows. The
    #: residual in negation_report() is entirely this: "not able to verify
    #: whether the server made the request" contains a confirmation cue
    #: inside the negation's scope, and a substring rule cannot tell.
    _SCOPING_MARKERS = (
        "not able to", "was not able", "unable to", "could not",
        "cannot", "could not determine", "not verified", "unverified",
        "did not verify", "no way to determine", "whether",
    )

    def _clause_scoped_inconclusive(self, context: str) -> tuple[bool, str]:
        """True when an inconclusive marker governs the rest of the clause.

        A deterministic approximation of negation scope: split on sentence
        boundaries, and if a scoping marker appears before a cue in the same
        clause, the cue sits inside its scope.
        """
        low = context.lower()
        for sentence in re.split(r"(?<=[.;])\s+", low):
            for marker in self._SCOPING_MARKERS:
                idx = sentence.find(marker)
                if idx < 0:
                    continue
                for cue in self.confirmation_cues:
                    cidx = sentence.find(cue)
                    if cidx > idx:
                        return True, f"scope:{marker}>...{cue}"
                for family, cues in self.negation_cues.items():
                    for cue in cues:
                        cidx = sentence.find(cue)
                        if cidx > idx and family != "inconclusive":
                            return True, f"scope:{marker}>...{cue}"
        return False, ""

    def classify(self, context: str) -> tuple[str, str]:
        """Return ``(verdict, cue)`` for a window of text."""
        low = context.lower()

        # Scope check precedes cue matching: a cue inside a negation's
        # scope is not evidence of a positive result.
        scoped, scope_cue = self._clause_scoped_inconclusive(context)
        if scoped:
            return Verdict.INCONCLUSIVE, scope_cue

        # Confirmation dominates: a sentence can say "could not rule out,
        # and indeed the server did make the request" and the confirmed
        # reading is the correct one.
        for cue in self.confirmation_cues:
            if cue in low:
                return Verdict.CONFIRMED, f"confirm:{cue}"

        # The inconclusive family is its own verdict, not a negation.
        # "Could not determine whether X" reports that the test did not
        # complete -- which is neither a finding nor a clean result, and
        # conflating it with either is what made the inconclusive arm
        # score 0.000.
        for cue in self.negation_cues.get("inconclusive", ()):
            if cue in low:
                return Verdict.INCONCLUSIVE, f"inconclusive:{cue}"
        for family, cues in self.negation_cues.items():
            if family == "inconclusive":
                continue
            for cue in cues:
                if cue in low:
                    return Verdict.NEGATED, f"{family}:{cue}"

        # No cue fired. The default is abstention, not confirmation.
        return Verdict.INCONCLUSIVE, "no_cue"

    # ── Resolution ────────────────────────────────────────────────────────

    def resolve(
        self, trace: ReasoningTrace, *, indicators: Mapping[str, Sequence[str]] | None = None
    ) -> list[Mention]:
        """Resolve every technique mentioned in *trace*."""
        table = dict(indicators if indicators is not None else ATTACK_INDICATORS)
        blob = trace.normalised()

        out: list[Mention] = []
        for technique, phrases in table.items():
            hits = _matches(blob, phrases)
            if not hits:
                continue
            # Widest context across every matched phrase, so a negation in
            # any clause of the step is seen.
            contexts = [self._context_around(blob, h) for h in hits]
            context = max(contexts, key=len) if contexts else blob
            verdict, cue = self.classify(context)
            out.append(Mention(technique, verdict, context, cue))

        out.sort(key=lambda m: (m.verdict != Verdict.CONFIRMED, m.technique))
        return out

    def coverage(self, trace: ReasoningTrace) -> frozenset[str]:
        """Techniques whose mention resolves to an actual test performed."""
        return frozenset(
            m.technique for m in self.resolve(trace) if m.counts_as_coverage
        )

    def spurious(self, trace: ReasoningTrace) -> frozenset[str]:
        """Techniques mentioned but negated — reported for audit, not action.

        These are exactly the cases the naive substring scorer flags and
        should not.
        """
        return frozenset(
            m.technique for m in self.resolve(trace)
            if m.verdict == Verdict.NEGATED
        )