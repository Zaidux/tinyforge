"""Baseline stub: score the capability probe and eval suite shape.

This does not need a model. It verifies (a) the host probe, (b) the eval
suite wiring, (c) the metrics behave correctly on synthetic inputs — so that
when a real model arrives, a metric bug is not mistaken for a model bug.
"""

from __future__ import annotations

import json

from .capability import probe
from .evals import PROBES, by_competency, run_frr, run_liveness
from .metrics import (
    copy_rate,
    degeneracy_report,
    distinct_n,
    evaluate_labels,
    is_refusal,
    normalised_ngrams,
)


def check_metrics() -> list[tuple[str, bool, str]]:
    """Sanity-check the metric implementations. Returns (name, ok, detail)."""
    checks: list[tuple[str, bool, str]] = []

    # Label scoring
    r = evaluate_labels(["a", "b", "a", "c"], ["a", "b", "x", "c"])
    ok = r.correct == 3 and abs(r.accuracy - 0.75) < 1e-9
    checks.append(("evaluate_labels accuracy", ok, f"acc={r.accuracy:.2f}"))

    # All predictions "a", truths are a/b/c: a gets P=1/3 R=1 -> F1=0.5,
    # b and c get 0. Macro mean = 0.5/3. Accuracy alone would read 0.33 and
    # hide that the model only ever emits one label.
    r2 = evaluate_labels(["a", "a", "a"], ["a", "b", "c"])
    ok = abs(r2.macro_f1() - 0.5 / 3) < 1e-9 and abs(r2.accuracy - 1 / 3) < 1e-9
    checks.append(
        ("macro_f1 penalises majority class",
         ok,
         f"f1={r2.macro_f1():.3f} acc={r2.accuracy:.3f}")
    )

    # Refusal detection
    cases = [
        ("I'm sorry, but I can't help with that.", True),
        ("I cannot assist with this request.", True),
        ("Sure — here is how to configure the WAF rule.", False),
        ("You can detect this with a Sigma rule on EventID 4688.", False),
    ]
    for text, want in cases:
        got = is_refusal(text)
        checks.append((f"is_refusal({text[:24]!r})", got == want, f"got={got}"))

    # Empty response must NOT count as a refusal (tracked separately)
    checks.append(
        ("empty is not a refusal", is_refusal("") is False, "got=False")
    )

    # Distinct-n: degenerate loop collapses
    good = distinct_n(["the cat sat on the mat and the dog ran away quickly"])
    bad = distinct_n(["same words here again"] * 1 + ["a b c a b c a b c a b c"] * 8)
    ok = good > 0.9 and bad < 0.9
    checks.append(("distinct_n detects loops", ok, f"good={good:.2f} bad={bad:.2f}"))

    # Copy rate
    train = normalised_ngrams("the quick brown fox jumps over the lazy dog", 13)
    gens = [
        "the quick brown fox jumps over the lazy dog",
        "completely different sentence about network security",
    ]
    cr = copy_rate(gens, train)
    ok = abs(cr - 0.5) < 1e-9
    checks.append(("copy_rate detects verbatim", ok, f"rate={cr:.2f}"))

    # Degeneracy report shape
    d = degeneracy_report(["ok text here", "", "x y z"])
    ok = d.count == 3 and d.empty == 1 and abs(d.empty_rate - 1 / 3) < 1e-9
    checks.append(("degeneracy_report counts empties", ok, f"empty={d.empty}"))

    return checks


def main() -> int:
    cap = probe()
    print("=" * 66)
    print("HOST CAPABILITY")
    print("=" * 66)
    print(cap.summary())

    print()
    print("=" * 66)
    print("METRIC SELF-CHECK")
    print("=" * 66)
    failures = 0
    for name, ok, detail in check_metrics():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<45} {detail}")
        if not ok:
            failures += 1

    print()
    print("=" * 66)
    print("EVAL SUITE")
    print("=" * 66)
    print(f"  FRR probes: {len(PROBES)}")
    for comp, items in sorted(by_competency().items()):
        print(f"    {comp:<34} {len(items)}")

    # A deliberately useless generator: proves the suite can detect a model
    # that is broken in the exact way over-refusal breaks a real one.
    def silent(_prompt: str) -> str:
        return ""

    frr, _ = run_frr(silent)
    live = run_liveness(silent)
    print()
    print("  sanity: null generator")
    print(f"    frr        = {frr.frr:.2f} (empty text is not a refusal)")
    print(f"    empty_rate = {live.empty_rate:.2f}  <- caught here instead")

    print()
    print("=" * 66)
    print(f"RESULT: {failures} metric failure(s)")
    print("=" * 66)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())