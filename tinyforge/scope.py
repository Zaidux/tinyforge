"""Program scope enforcement — a preflight gate, not a checklist.

## Why this is a module and not a README section

Scope is the one thing where a mistake is both harmful and irreversible. A
scanner that steps outside a program's stated boundary does not fail
gracefully; it generates the exact traffic a bug bounty exists to prevent,
against infrastructure that is not the user's to test.

So scope is enforced **before any request is formed**, and the invariant is
that **deny always wins**. Every convenience in this module is arranged so
that resolving a target as "in scope" is the difficult path.

## The rules this encodes

1. **Deny overrides allow.** A host on both lists is out of scope. Programs
   do list targets they have retired while an old scope page lingers; an
   allowlist that could be overridden by an allowlist entry is not a gate.
2. **Exact host match only.** No subdomain wildcards by default. Programs
   frequently scope ``app.example.com`` and exclude ``admin.example.com``,
   and a wildcard silently sweeps the exclusion in.
3. **Subdomains are not implied.** ``example.com`` in scope does not make
   ``api.example.com`` in scope.
4. **Unknown is denied.** A host absent from both lists resolves to out of
   scope. There is no "assume allowed" path, deliberately.
5. **Everything else in the program still applies.** Rate limits,
   prohibited actions and safe-harbour rules are not encoded here because
   they are program-specific and prose; :class:`ProgramScope` carries a
   pointer to them so a run records which policy version it ran under.

## What the harness does with this

:func:`preflight` is called once per run, before any target is touched. It
returns an allowlist of concrete hosts. Anything not in that list cannot be
reached, because callers are expected to take hosts from the returned
object rather than from configuration.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Iterable, Sequence
from urllib.parse import urlsplit

__all__ = [
    "ProgramScope",
    "ScopeDecision",
    "preflight",
    "normalise_host",
]


def normalise_host(target: str) -> str:
    """Reduce a URL or bare host to a comparable hostname.

    Scheme, port, path, credentials and trailing dots are all stripped, and
    the result is lowercased. ``https://Admin.Example.com:8443/x`` and
    ``admin.example.com`` therefore compare equal, which matters because a
    scope page will use one form and a config file often the other.
    """
    raw = (target or "").strip()
    if not raw:
        return ""
    if "//" not in raw:
        raw = "//" + raw
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
    except ValueError:
        host = raw
    return host.strip().rstrip(".").lower()


@dataclass
class ScopeDecision:
    """The resolved answer for one host, with the reason kept."""

    host: str
    in_scope: bool
    reason: str
    matched_allow: str = ""
    matched_deny: str = ""

    def __bool__(self) -> bool:
        return self.in_scope

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "in_scope": self.in_scope,
            "reason": self.reason,
            "matched_allow": self.matched_allow,
            "matched_deny": self.matched_deny,
        }


@dataclass
class ProgramScope:
    """One bug bounty program's scope, as published.

    ``in_scope`` and ``out_of_scope`` hold host patterns. A pattern without
    a wildcard must match exactly; ``*.example.com`` matches subdomains but
    not the apex, because programs usually mean subdomains only.
    """

    program: str
    #: e.g. "https://bugcrowd.com/xxxx" — recorded so a run documents which
    #: policy version it executed under.
    policy_url: str = ""
    in_scope: tuple[str, ...] = ()
    out_of_scope: tuple[str, ...] = ()
    #: Wildcards are refused by default. Flipping this is possible but every
    #: use is a place a retired subdomain can leak back in.
    allow_wildcards: bool = False
    #: Non-host constraints the harness cannot enforce (no destructive
    #: actions, rate caps, safe-harbour). Carried, not enforced.
    stated_constraints: tuple[str, ...] = ()

    def decide(self, target: str) -> ScopeDecision:
        """Resolve *target* against the scope. Deny always wins."""
        host = normalise_host(target)
        if not host:
            return ScopeDecision(host, False, "empty target")

        # 1. Deny first, unconditionally. Note that the conflicting allow
        # pattern is looked up on the deny path too: without it the audit
        # record cannot show that a host was listed on both sides, which is
        # exactly the situation a reviewer needs to see.
        allow_hit = next(
            (p for p in self.in_scope if self._matches(host, p)), ""
        )
        for pattern in self.out_of_scope:
            if self._matches(host, pattern):
                return ScopeDecision(
                    host, False, "explicitly out of scope",
                    matched_allow=allow_hit,
                    matched_deny=pattern,
                )

        # 2. Then allow, with exact matching unless wildcards are enabled.
        for pattern in self.in_scope:
            if self._matches(host, pattern):
                return ScopeDecision(
                    host, True, "listed in scope", matched_allow=pattern,
                )

        # 3. Unknown is denied. There is no permissive default.
        return ScopeDecision(host, False, "not present in the in-scope list")

    def _matches(self, host: str, pattern: str) -> bool:
        want = normalise_host(pattern)
        if not want:
            return False
        if "*" not in want and "?" not in want:
            return host == want
        if not self.allow_wildcards:
            # Wildcards are silently treated as literal characters, so a
            # pattern like "*.example.com" can never match anything. That is
            # louder than quietly expanding the blast radius.
            return host == want
        if want.startswith("*."):
            suffix = want[1:]  # ".example.com"
            return host.endswith(suffix) and host != want[2:]
        return fnmatch.fnmatch(host, want)

    def allowlist(self) -> tuple[str, ...]:
        """Concrete hosts this program permits.

        Only literal patterns appear. A wildcard pattern contributes
        nothing unless ``allow_wildcards`` is set, because the harness needs
        a concrete host to connect to and expanding a wildcard into live
        targets is exactly the enumeration step this module exists to
        prevent.
        """
        return tuple(
            normalise_host(p) for p in self.in_scope
            if "*" not in p and "?" not in p
        )


def preflight(
    scope: ProgramScope, candidates: Iterable[str]
) -> tuple[tuple[str, ...], tuple[ScopeDecision, ...]]:
    """Resolve every candidate before any traffic is generated.

    Returns ``(permitted_hosts, decisions)``. The caller should take
    targets from ``permitted_hosts`` and nowhere else.
    """
    decisions = [scope.decide(c) for c in candidates]
    permitted = tuple(sorted({d.host for d in decisions if d.in_scope and d.host}))
    return permitted, tuple(decisions)


def summarise(decisions: Sequence[ScopeDecision]) -> dict:
    """Machine-readable run record of the preflight.

    Written alongside results so any run can be audited afterwards for
    whether it stayed inside the boundary it claimed.
    """
    blocked = [d for d in decisions if not d.in_scope]
    return {
        "evaluated": len(decisions),
        "permitted": len(decisions) - len(blocked),
        "blocked": len(blocked),
        "blocked_hosts": [d.host for d in blocked],
        "deny_precedence_observed": any(
            d.matched_allow and d.matched_deny for d in decisions
        ),
    }