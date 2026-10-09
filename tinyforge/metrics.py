"""Metrics for tinyforge evaluation.

Two families matter here, and the second one is the one that usually gets
skipped:

**Task metrics** — accuracy on classification-style tasks where a label
exists.

**Degeneracy metrics** — the failure modes a small model exhibits that a
large model does not, and that aggregate accuracy hides entirely. IBM makes
the point about Granite in its own model card: smaller models "might exhibit
increased susceptibility to hallucination in generation scenarios by copying
text verbatim from the training dataset due to their reduced sizes and
memorization capacities." A model that recites instead of confabulating is a
*different* failure mode, and in a security context a confidently wrong CVE ID
is worse than an admission of ignorance.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Sequence


@dataclass
class ClassScore:
    """Per-class true-positive / predicted / actual counts."""

    tp: int = 0
    predicted: int = 0
    actual: int = 0

    @property
    def precision(self) -> float:
        return self.tp / self.predicted if self.predicted else 0.0

    @property
    def recall(self) -> float:
        return self.tp / self.actual if self.actual else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


@dataclass
class LabelResult:
    """Accuracy plus per-class detail for a classification eval."""

    total: int
    correct: int
    per_class: dict[str, ClassScore] = field(default_factory=dict)
    confusions: Counter = field(default_factory=Counter)

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    def macro_f1(self) -> float:
        """Unweighted mean F1 over classes that actually appear in the labels.

        Prefer this over accuracy for CWE/technique classification: those
        label sets are long-tailed, and a model that only ever predicts the
        top-3 classes scores respectable accuracy while being useless.
        """
        scored = [s for s in self.per_class.values() if s.actual > 0]
        return sum(s.f1 for s in scored) / len(scored) if scored else 0.0


def evaluate_labels(
    predictions: Sequence[str], labels: Sequence[str]
) -> LabelResult:
    """Score a classification run. Raises if lengths disagree."""
    if len(predictions) != len(labels):
        raise ValueError(
            f"prediction/label length mismatch: {len(predictions)} vs {len(labels)}"
        )

    per_class: dict[str, ClassScore] = {}
    confusions: Counter = Counter()
    correct = 0

    for pred, truth in zip(predictions, labels):
        truth_score = per_class.setdefault(truth, ClassScore())
        truth_score.actual += 1

        pred_score = per_class.setdefault(pred, ClassScore())
        pred_score.predicted += 1

        if pred == truth:
            correct += 1
            pred_score.tp += 1
        else:
            confusions[(truth, pred)] += 1

    return LabelResult(
        total=len(labels),
        correct=correct,
        per_class=per_class,
        confusions=confusions,
    )


# ── Refusal detection ──────────────────────────────────────────────────────

# Phrases that indicate a refusal rather than an answer. Deliberately broad:
# under-detecting refusal inflates the usefulness score and hides the exact
# failure this metric exists to catch.
_REFUSAL_PATTERNS = (
    r"\bi can'?t help\b",
    r"\bi cannot help\b",
    r"\bi can'?t assist\b",
    r"\bi cannot assist\b",
    r"\bi'?m not able to help\b",
    r"\bi am not able to help\b",
    r"\bi won'?t help\b",
    r"\bi will not help\b",
    r"\bi'?m unable to (help|assist|provide)\b",
    r"\bi am unable to (help|assist|provide)\b",
    r"\bi can'?t (provide|share|give) (information|details)\b",
    r"\bsorry,? (but )?i can'?t\b",
    r"\bi must decline\b",
    r"\bi'?m not going to help\b",
    r"\bagainst my (guidelines|policy|policies)\b",
    r"\bi'?m not comfortable\b",
    r"\bthat'?s (something )?i can'?t\b",
    r"\bunable to comply\b",
    r"\bi don'?t think i should\b",
    r"\bas an ai\b.{0,40}\b(cannot|can'?t|unable)\b",
)

_REFUSAL_RE = re.compile("|".join(_REFUSAL_PATTERNS), re.IGNORECASE)


def is_refusal(text: str) -> bool:
    """True when *text* refuses rather than answers.

    Deliberately does not treat an empty response as a refusal — an empty
    response is a *degeneracy* signal tracked separately by
    :func:`degeneracy_report`, because conflating the two hides which bug
    you actually have.
    """
    return bool(_REFUSAL_RE.search(text or ""))


# ── Degeneracy detection ────────────────────────────────────────────────────

_WORD_RE = re.compile(r"\b\w+\b")
_WHITESPACE_RE = re.compile(r"\s+")


def normalised_ngrams(text: str, n: int = 13) -> set[str]:
    """Character n-grams of *text*, whitespace-collapsed.

    Character n-grams rather than words: security identifiers do not
    respect word boundaries (``T1059.001`` and ``T1059.002`` differ by one
    character), and a word-level copy detector would miss exactly the
    memorisation we care about here.
    """
    collapsed = _WHITESPACE_RE.sub(" ", (text or "").strip().lower())
    if len(collapsed) < n:
        return {collapsed} if collapsed else set()
    return {collapsed[i : i + n] for i in range(len(collapsed) - n + 1)}


def copy_rate(
    generations: Sequence[str], training_ngrams: Iterable[str]
) -> float:
    """Fraction of generations that reproduce training text verbatim.

    *training_ngrams* should be character n-grams drawn from the training
    split. The caller is responsible for splitting by **source document**,
    not by random row — a random split leaks source text across the boundary
    and makes this metric return zero no matter how much the model memorised.
    """
    train = set(training_ngrams)
    if not train:
        raise ValueError(
            "training_ngrams is empty — the caller must pass n-grams from the "
            "training split; an empty set makes copy_rate meaningless"
        )

    copied = sum(
        1 for gen in generations if normalised_ngrams(gen, 13) & train
    )
    return copied / len(generations) if generations else 0.0


def distinct_n(texts: Sequence[str], n: int = 3) -> float:
    """Type/token ratio over word n-grams — a degeneration signal.

    A model stuck in a repetition loop collapses this toward zero even while
    producing fluent-looking text.
    """
    total = 0
    unique: set[tuple[str, ...]] = set()
    for text in texts:
        words = _WORD_RE.findall((text or "").lower())
        grams = [tuple(words[i : i + n]) for i in range(max(0, len(words) - n + 1))]
        total += len(grams)
        unique.update(grams)
    return len(unique) / total if total else 0.0


@dataclass
class DegeneracyReport:
    """Degeneracy signals over a set of generations."""

    count: int
    empty: int
    empty_rate: float
    distinct_ngram: float
    copy_rate: float
    mean_length_words: float
    repeated_loop_suspects: int

    def as_dict(self) -> dict:
        return {
            "count": self.count,
            "empty": self.empty,
            "empty_rate": round(self.empty_rate, 4),
            "distinct_ngram": round(self.distinct_ngram, 4),
            "copy_rate": round(self.copy_rate, 4),
            "mean_length_words": round(self.mean_length_words, 1),
            "repeated_loop_suspects": self.repeated_loop_suspects,
        }


def _loop_suspect(text: str, window: int = 40) -> bool:
    """True when *text* repeats a short block — the classic decoding stall."""
    collapsed = _WHITESPACE_RE.sub(" ", (text or "").strip().lower())
    if len(collapsed) < window * 2:
        return False
    for i in range(0, min(len(collapsed) - window, 400), 10):
        block = collapsed[i : i + window]
        if collapsed.find(block, i + window) != -1:
            return True
    return False


def degeneracy_report(
    generations: Sequence[str], training_ngrams: Iterable[str] | None = None
) -> DegeneracyReport:
    """Summarise how a generation batch is behaving.

    *training_ngrams* enables the copy-rate check. When omitted, copy rate is
    reported as 0.0 — which means "not measured", not "no copying". Do not
    present an unmeasured copy rate as a pass.
    """
    words = [len((g or "").split()) for g in generations]
    empty = sum(1 for g in generations if not (g or "").strip())

    rate = 0.0
    if training_ngrams is not None:
        collected = set(training_ngrams)
        if collected:
            rate = copy_rate(generations, collected)

    return DegeneracyReport(
        count=len(generations),
        empty=empty,
        empty_rate=empty / len(generations) if generations else 0.0,
        distinct_ngram=distinct_n(generations),
        copy_rate=rate,
        mean_length_words=sum(words) / len(words) if words else 0.0,
        repeated_loop_suspects=sum(1 for g in generations if _loop_suspect(g)),
    )


# ── Latency ─────────────────────────────────────────────────────────────────


@dataclass
class LatencyResult:
    """Latency and memory for a single-batch decode on this host."""

    model: str
    params: int
    prompt_tokens: int
    generated_tokens: int
    first_token_s: float
    total_s: float
    peak_rss_mib: float

    @property
    def tokens_per_s(self) -> float:
        if self.total_s <= 0:
            return 0.0
        return self.generated_tokens / self.total_s

    def as_dict(self) -> dict:
        return {
            "model": self.model,
            "params": self.params,
            "prompt_tokens": self.prompt_tokens,
            "generated_tokens": self.generated_tokens,
            "first_token_s": round(self.first_token_s, 3),
            "total_s": round(self.total_s, 3),
            "tokens_per_s": round(self.tokens_per_s, 2),
            "peak_rss_mib": round(self.peak_rss_mib, 1),
        }


def read_peak_rss_mib() -> float:
    """Current peak RSS of this process in MiB, or 0.0 if unavailable."""
    try:
        with open("/proc/self/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


def perplexity(logprobs: Sequence[float]) -> float:
    """Perplexity from a sequence of token log-probabilities."""
    if not logprobs:
        return float("inf")
    return math.exp(-sum(logprobs) / len(logprobs))