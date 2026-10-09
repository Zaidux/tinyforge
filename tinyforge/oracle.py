"""LLM backend for A/B experiments.

The oracle model is what we measure *against*. It stands in for the "large
model" in the paired design: run task T with the oracle alone (condition A),
then with oracle + scorer (condition B), and compare.

Design constraints, in priority order:

1. **Credentials never touch disk or logs.** The key is read from the
   environment at call time. Nothing in this module writes a key, and
   ``describe()`` deliberately reports only whether a key is *present*.
2. **Every call is recorded**, including failures. An A/B where the
   treatment arm silently drops requests produces a fake win.
3. **Deterministic by default.** ``temperature=0`` unless overridden,
   because a paired comparison with a stochastic oracle measures the
   oracle's variance, not the scorer's effect.

Providers on this box (verified 2026-10-09):
  zen / space-bunny-free     — works, ~2-4s, OpenAI-compatible
  iamhc / DeepSeek-V4-Flash  — works, ~4-10s, exposes reasoning_tokens
  zen-go / deepseek-v4-pro   — key present but requires an active Go
                              subscription; returns HTTP 403 "An active
                              OpenCode Go subscription is required"
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

__all__ = [
    "LLMResponse",
    "OracleConfig",
    "Oracle",
    "PROVIDERS",
]

_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

#: Known provider endpoints, all verified by live call on 2026-10-09.
#:
#: Note the distinction between ``zen`` and ``zen/go``: they are different
#: products with different entitlements. ``/zen/v1`` serves the free tier
#: including ``space-bunny-free``; ``/zen/go/v1`` serves the paid Go models
#: and rejects the friend key with HTTP 403.
PROVIDERS: dict[str, dict[str, str]] = {
    "zen": {
        "base_url": "https://opencode.ai/zen/v1",
        "api_key_env": "OPENCODE_FRIEND_API_KEY",
        "default_model": "space-bunny-free",
    },
    "iamhc": {
        "base_url": "https://api.iamhc.cn/v1",
        "api_key_env": "IAMHC_API_KEY",
        "default_model": "DeepSeek-V4-Flash",
    },
    "zen-go": {
        "base_url": "https://opencode.ai/zen/go/v1",
        "api_key_env": "OPENCODE_FRIEND_API_KEY",
        "default_model": "deepseek-v4-pro",
        "note": "requires an active OpenCode Go subscription (HTTP 403)",
    },
}


@dataclass
class LLMResponse:
    """One model response, with the accounting an A/B needs."""

    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    latency_s: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def as_dict(self) -> dict:
        return {
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "latency_s": round(self.latency_s, 3),
            "error": self.error,
        }


@dataclass
class OracleConfig:
    """Which model to call and how."""

    provider: str = "zen"
    model: str = ""
    temperature: float = 0.0
    max_tokens: int = 512
    timeout_s: float = 90.0
    system_prompt: str = ""

    def resolved_model(self) -> str:
        if self.model:
            return self.model
        return PROVIDERS[self.provider]["default_model"]


@dataclass
class Oracle:
    """Thin, dependency-free client for the oracle model."""

    config: OracleConfig = field(default_factory=OracleConfig)
    calls: list[LLMResponse] = field(default_factory=list)

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def key_available(self) -> bool:
        return bool(os.environ.get(self._key_env))

    @property
    def _key_env(self) -> str:
        return PROVIDERS[self.config.provider]["api_key_env"]

    def describe(self) -> dict:
        """Safe-to-log summary. Never includes key material."""
        provider = PROVIDERS[self.config.provider]
        return {
            "provider": self.config.provider,
            "base_url": provider["base_url"],
            "model": self.config.resolved_model(),
            "key_present": self.key_available,
            "key_env": self._key_env,
            "temperature": self.config.temperature,
            "calls_made": len(self.calls),
        }

    # ── Calling ───────────────────────────────────────────────────────────

    def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Single completion. Failures are returned, not raised."""
        provider = PROVIDERS[self.config.provider]
        key = os.environ.get(provider["api_key_env"])
        model = self.config.resolved_model()
        temp = self.config.temperature if temperature is None else temperature
        cap = self.config.max_tokens if max_tokens is None else max_tokens

        if not key:
            resp = LLMResponse(
                text="", model=model,
                error=f"missing API key (env {provider['api_key_env']})",
            )
            self.calls.append(resp)
            return resp

        messages: list[dict[str, str]] = []
        sys = system or self.config.system_prompt
        if sys:
            messages.append({"role": "system", "content": sys})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps(
            {
                "model": model,
                "messages": messages,
                "temperature": temp,
                "max_tokens": cap,
            }
        ).encode()

        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": _UA,
            "Accept": "application/json",
        }
        # opencode-go routes on a session header; harmless elsewhere.
        headers["x-opencode-session"] = f"tinyforge-{uuid.uuid4().hex[:12]}"

        request = urllib.request.Request(
            f"{provider['base_url'].rstrip('/')}/chat/completions",
            data=payload,
            headers=headers,
        )

        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_s) as raw:
                body = json.loads(raw.read())
            usage = body.get("usage") or {}
            details = usage.get("completion_tokens_details") or {}
            resp = LLMResponse(
                text=(body["choices"][0]["message"].get("content") or ""),
                model=body.get("model", model),
                prompt_tokens=int(usage.get("prompt_tokens") or 0),
                completion_tokens=int(usage.get("completion_tokens") or 0),
                reasoning_tokens=int(details.get("reasoning_tokens") or 0),
                latency_s=time.perf_counter() - started,
            )
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:200].decode("utf-8", "replace")
            resp = LLMResponse(
                text="", model=model,
                latency_s=time.perf_counter() - started,
                error=f"HTTP {exc.code}: {detail}",
            )
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            resp = LLMResponse(
                text="", model=model,
                latency_s=time.perf_counter() - started,
                error=f"{type(exc).__name__}: {exc}",
            )

        self.calls.append(resp)
        return resp

    def complete_many(
        self, prompts: Sequence[str], *, progress: Callable[[int, int], None] | None = None
    ) -> list[LLMResponse]:
        for i, p in enumerate(prompts):
            self.complete(p)
            if progress:
                progress(i + 1, len(prompts))
        return list(self.calls)

    # ── Accounting ────────────────────────────────────────────────────────

    def usage(self) -> dict[str, int]:
        return {
            "calls": len(self.calls),
            "prompt_tokens": sum(c.prompt_tokens for c in self.calls),
            "completion_tokens": sum(c.completion_tokens for c in self.calls),
            "failures": sum(1 for c in self.calls if c.error),
            "total_latency_s": round(sum(c.latency_s for c in self.calls), 2),
        }