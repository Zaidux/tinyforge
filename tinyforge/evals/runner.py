"""Eval runner: FRR + degeneracy + latency for a given generator.

A *generator* is any callable taking a prompt string and returning text.
That keeps this layer decoupled from how the model is loaded, so the same
suite scores a numpy scratch model, a LoRA student, and a frontier API
baseline without changes.

The head-to-head comparison against a larger model on this same suite is
the experiment worth running: show the small model winning on latency, cost,
and privacy while the frontier model wins on open-ended reasoning. An honest
Pareto frontier is a better result than a cherry-picked win.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from ..metrics import (
    DegeneracyReport,
    LatencyResult,
    degeneracy_report,
    is_refusal,
    read_peak_rss_mib,
)
from .frr_probes import PROBES, Probe, by_competency

Generator = Callable[[str], str]


@dataclass
class FrrResult:
    """False Refusal Rate, overall and per NICE competency."""

    total: int
    refusals: int
    by_competency: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def frr(self) -> float:
        return self.refusals / self.total if self.total else 0.0

    def per_competency_frr(self) -> dict[str, float]:
        return {
            comp: (refused / total if total else 0.0)
            for comp, (refused, total) in self.by_competency.items()
        }

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "refusals": self.refusals,
            "frr": round(self.frr, 4),
            "per_competency": {
                k: round(v, 4) for k, v in self.per_competency_frr().items()
            },
        }


def run_frr(
    generate: Generator,
    probes: Sequence[Probe] = PROBES,
    *,
    max_chars: int = 2000,
) -> tuple[FrrResult, list[tuple[Probe, str, bool]]]:
    """Measure False Refusal Rate over *probes*.

    Returns the aggregate plus the per-probe transcript so a human can audit
    the refusals — an FRR number with no transcript is not trustworthy,
    because the refusal regex may be firing on an unrelated phrase.
    """
    per_comp: dict[str, tuple[int, int]] = {}
    transcript: list[tuple[Probe, str, bool]] = []
    refusals = 0

    for probe in probes:
        text = (generate(probe.prompt) or "")[:max_chars]
        refused = is_refusal(text)
        refusals += int(refused)
        r, t = per_comp.get(probe.nice_competency, (0, 0))
        per_comp[probe.nice_competency] = (r + int(refused), t + 1)
        transcript.append((probe, text, refused))

    return (
        FrrResult(total=len(probes), refusals=refusals, by_competency=per_comp),
        transcript,
    )


def run_liveness(
    generate: Generator,
    probes: Sequence[Probe] = PROBES,
) -> DegeneracyReport:
    """Check the model produces non-empty, non-degenerate output.

    A model can score a perfect FRR of 0.0 by refusing everything *and*
    emitting nothing. This catches that.
    """
    generations = [(generate(p.prompt) or "") for p in probes]
    return degeneracy_report(generations)


def measure_latency(
    generate: Generator,
    prompt: str,
    *,
    model: str = "unknown",
    params: int = 0,
) -> LatencyResult:
    """Time one decode and record peak RSS.

    Peak RSS is read from ``/proc/self/status`` VmHWM, so it reflects this
    process's high-water mark — which on a fresh process is the honest
    number, provided you run it as its own process.
    """
    before = read_peak_rss_mib()
    t0 = time.perf_counter()
    text = generate(prompt) or ""
    total = time.perf_counter() - t0

    first = total if not text else 0.0
    approx_tokens = max(1, len(text.split()))
    peak = max(before, read_peak_rss_mib())

    return LatencyResult(
        model=model,
        params=params,
        prompt_tokens=len(prompt.split()),
        generated_tokens=approx_tokens,
        first_token_s=first,
        total_s=total,
        peak_rss_mib=peak,
    )


def full_report(
    generate: Generator,
    *,
    model: str = "unknown",
    params: int = 0,
    training_ngrams: Iterable[str] | None = None,
) -> dict:
    """Run every metric and return one JSON-serialisable report."""
    frr, transcript = run_frr(generate)
    liveness = run_liveness(generate)
    latency = measure_latency(
        generate, PROBES[0].prompt if PROBES else "hello", model=model, params=params
    )

    return {
        "model": model,
        "params": params,
        "frr": frr.as_dict(),
        "degeneracy": liveness.as_dict(),
        "latency": latency.as_dict(),
        "transcript": [
            {"uid": p.uid, "nice": p.nice_competency, "refused": refused,
             "response": text[:400]}
            for p, text, refused in transcript
        ],
        "competency_coverage": sorted(by_competency().keys()),
    }


def dump_report(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)