"""Recon from published API specifications and route inventories.

## Why this exists

The first applicability measurement showed recall of 0.60, and the residual
misses clustered on one axis: ``sql_injection`` and ``nosql_injection`` on a
partial surface, where our observation set was sparse. That is a
**recon-coverage** problem, not a predicate problem, and it cannot be fixed
by writing more rules.

Hand-written observations were the bottleneck. An API specification is
better evidence than anything we invent: it is authored by the application,
it enumerates real endpoints, and it states the auth scheme explicitly.

## What is extracted

From an OpenAPI document:

* every path — which is an **endpoint inventory**, the single most valuable
  recon artefact for applicability
* security schemes, which settles token transport (cookie vs header) — the
  fact four of eleven inter-judge disagreements turned on in
  APPLICABILITY.md
* declared parameters and body fields

Derived facts are still inferred through :mod:`tinyforge.targets`, so the
conservatism rules apply unchanged: absence of a signal leaves a fact unset.

## A word on scope

Only applications whose own repositories publish their specifications are
in scope, and only offline parsing. Nothing here sends a request to a
third-party host.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .targets import Observation, build_target

__all__ = [
    "ApiSurface",
    "observations_from_openapi",
    "security_scheme_facts",
    "build_surface_target",
]


@dataclass
class ApiSurface:
    """A parsed API specification, before fact inference."""

    name: str
    app: str
    #: Paths declared by the specification.
    paths: tuple[str, ...] = ()
    #: Security scheme names, e.g. {"bearerAuth"}.
    security_schemes: tuple[str, ...] = ()
    #: Security scheme type/scheme pairs, e.g. {"bearerAuth": "http/bearer"}.
    scheme_details: dict = field(default_factory=dict)
    #: Request body and query parameter names seen.
    parameters: tuple[str, ...] = ()
    #: Response content types observed in the spec.
    content_types: tuple[str, ...] = ()
    #: Declared HTTP methods per path.
    methods: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    def as_observations(self) -> list[Observation]:
        """Render as recon observations, for the existing inference path."""
        obs: list[Observation] = []

        for path in self.paths:
            obs.append(Observation("endpoint", path, f"{self.name} spec"))
            methods = self.methods.get(path) or []
            if methods:
                obs.append(
                    Observation("method", f"{','.join(methods)} {path}",
                                f"{self.name} spec")
                )

        for name in self.security_schemes:
            detail = self.scheme_details.get(name, "")
            obs.append(
                Observation("source", f"securityScheme {name} {detail}",
                            f"{self.name} spec")
            )
            # Render the scheme so existing token-transport signals match.
            if "bearer" in detail.lower():
                obs.append(
                    Observation("header", "Authorization: Bearer <token>",
                                f"{self.name} securitySchemes.{name}")
                )
            if "cookie" in detail.lower() or "apikey" in detail.lower():
                obs.append(
                    Observation("header", "Set-Cookie: session=<token>",
                                f"{self.name} securitySchemes.{name}")
                )

        for param in self.parameters:
            obs.append(Observation("source", f"parameter {param}",
                                   f"{self.name} spec"))
        for ct in self.content_types:
            obs.append(
                Observation("header", f"Content-Type: {ct}", f"{self.name} spec")
            )
        return obs


def _parse_security(doc: dict) -> tuple[tuple[str, ...], dict]:
    schemes = ((doc.get("components") or {}).get("securitySchemes") or {})
    names = tuple(schemes)
    details = {}
    for name, spec in schemes.items():
        parts = [str(spec.get("type", ""))]
        for key in ("scheme", "in", "bearerFormat"):
            if key in spec:
                parts.append(str(spec[key]))
        details[name] = "/".join(p for p in parts if p)
    return names, details


def _walk_schema(node, found: set[str], depth: int = 0) -> None:
    if depth > 12 or not isinstance(node, dict):
        return
    for key, value in node.items():
        if key in ("properties", "parameters") and isinstance(value, dict):
            for prop_key in value:
                found.add(str(prop_key))
        elif key in ("schema", "items", "requestBody", "responses", "content",
                     "paths", "post", "get", "put", "delete", "patch",
                     "components", "schemas", "securitySchemes",
                     "allOf", "anyOf", "oneOf"):
            _walk_schema(value, found, depth + 1)
        elif isinstance(value, (dict, list)):
            _walk_schema(value, found, depth + 1)


def observations_from_openapi(
    doc: dict, *, name: str = "api", app: str = "unknown"
) -> ApiSurface:
    """Extract endpoints, auth scheme, parameters and content types."""
    paths = tuple((doc.get("paths") or {}).keys())
    names, details = _parse_security(doc)

    methods: dict[str, list[str]] = {}
    for path, ops in (doc.get("paths") or {}).items():
        if isinstance(ops, dict):
            found = [
                m.upper() for m in ops
                if m.lower() in ("get", "post", "put", "patch", "delete", "head")
            ]
            if found:
                methods[path] = found

    params: set[str] = set()
    content_types: set[str] = set()
    # Component schemas are the $ref targets of path schemas. Without
    # walking them, every identifier that lives in a named schema is
    # invisible -- which is most of them in a real specification.
    _walk_schema(doc.get("components") or {}, params)
    for path, ops in (doc.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        _walk_schema(ops, params)
        for op in ops.values():
            if isinstance(op, dict):
                for resp in (op.get("responses") or {}).values():
                    if isinstance(resp, dict):
                        for ct in ((resp.get("content") or {}).keys()):
                            content_types.add(str(ct))

    return ApiSurface(
        name=name,
        app=app,
        paths=paths,
        security_schemes=names,
        scheme_details=details,
        parameters=tuple(sorted(params)),
        content_types=tuple(sorted(content_types)),
        methods=methods,
        raw=doc,
    )


def security_scheme_facts(surface: ApiSurface) -> dict[str, bool]:
    """What the spec tells us about auth transport, without guessing.

    ``apiKey in cookie`` means ambient, which is what makes CSRF relevant.
    ``http bearer`` means header-borne, which makes CSRF not applicable and
    CORS the concern. This is exactly the distinction the judges could not
    resolve from our previous observations.
    """
    cookie = False
    header = False
    for detail in surface.scheme_details.values():
        low = detail.lower()
        if "cookie" in low or ("apikey" in low and "query" not in low and "header" not in low):
            cookie = True
        if "bearer" in low or "basic" in low or "header" in low or "apikey" in low:
            header = True
    return {"has_cookie_auth": cookie, "has_header_auth": header}


def build_surface_target(
    surface: ApiSurface,
    *,
    target_id: str,
    module: str = "api",
    stack: Sequence[str] = (),
    documented_classes: Sequence[str] = (),
    description: str = "",
    source_url: str = "",
    extra_observations: Sequence[Observation] = (),
):
    """Build a :class:`~tinyforge.targets.ReconTarget` from a spec surface.

    The explicit auth facts from the spec are added *after* inference rather
    than being inferred from a regex, because the specification states the
    transport directly and a regex is strictly worse at reading it.
    """
    obs = list(surface.as_observations()) + list(extra_observations)
    target = build_target(
        target_id,
        surface.app,
        module,
        obs,
        description=description or f"{surface.name} API surface",
        stack=stack,
        documented_classes=documented_classes,
        source_url=source_url,
    )
    # The spec is authoritative on auth transport.
    for fact, value in security_scheme_facts(surface).items():
        if value:
            target.facts[fact] = True
            target.fact_provenance.setdefault(fact, []).append(
                f"declared in {surface.name} securitySchemes"
            )
    return target