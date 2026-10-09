# Data specification

What we will generate, why each source exists, and what every record must
carry. This is the contract the generators are written against — code that
does not conform here is wrong regardless of how good it looks.

## Status

**Pre-generation.** No data has been produced. This document specifies what
*would* be produced so the generators can be built against a fixed target.

## The headline finding that shapes all of this

There is **no published dataset of security-agent blind spots with ground
truth.** Benchmarks measure *did the agent solve it*; none label *what it
never tried that it should have tried*. We are not filling a gap in an
existing corpus — we are establishing the corpus. That is the contribution,
and it means the spec has to carry more of the burden than it otherwise
would.

## Phase map

| Phase | Deliverable | Depends on |
|---|---|---|
| 0 | Capability probe, eval suite, metrics | — ✅ done |
| 1 | Design pivot to scorer architecture | — ✅ done |
| 2 | Measurement power analysis | — ✅ done |
| 3 | Coverage + blind-spot + hallucination detectors | — ✅ done |
| 4 | Oracle backend, paired A/B harness | — ✅ done |
| 5 | **Applicability function** | — ✅ done |
| 6 | **Constrained task prompts + baseline A/B** | ⏳ next |
| 7 | **Null-scorer baseline run** | phase 6 |
| 8 | **Data generation** | phase 7 |
| 9 | Model training | phase 7, 8 |
| 10 | Scaled A/B, Pareto report | phase 9 |

Phase 8 is data generation. It is gated on phase 7 deliberately: if the
deterministic rules do not move the metric, a trained model will not either,
and generating 120k examples to learn that would be waste.

## Record schema

Every generated record carries provenance. Without it the copy-rate metric
cannot separate memorisation from generalisation, and the degeneracy story
collapses.

```json
{
  "example_id": "g2_technique_7f3a_0042",
  "generator": "G2_technique_gap",
  "seed": 8412993,
  "target_profile": "rest_api_jwt",
  "profile_facts": {"uses_jwt": true, "has_object_ids": true},
  "trajectory": {
    "steps": [
      {"i": 0, "type": "tool", "tool": "nmap",
       "output_digest": "80/tcp http 443/tcp https",
       "evidence_kind": "port_scan"},
      {"i": 3, "type": "finding", "text": "IDOR confirmed on /orders/{id}",
       "asserts": ["idor"], "evidence_refs": [1, 2],
       "supported": true}
    ]
  },
  "tools_available": ["nmap", "sqlmap", "jwt_tool", "curl"],
  "tools_invoked": ["nmap", "curl"],
  "applicable_techniques": ["idor", "bfa", "jwt", "sql_injection"],
  "gaps": {
    "tool": [], "technique": [{"id": "jwt", "why_applicable": ["uses_jwt=True"]}],
    "hallucination": []
  },
  "negative": false,
  "provenance": {"source": "synthetic", "generator_version": "1.0",
                 "license": "project-owned"}
}
```

Non-negotiable fields:

- **`profile_facts`** — the observables that produced applicability. Without
  them a gap label is unfalsifiable.
- **`evidence_refs`** on every finding — makes hallucination detection a
  *relational* check (is there a supporting step?) rather than a linguistic
  one. This is what lets a non-language model do it.
- **`negative`** — roughly 40% of records. A corpus with only positive cases
  trains a scorer that flags everything.

## Source taxonomy

### S1 — Synthetic trajectories (primary, ~88% of records)

Four generators, each emitting the record schema above.

| Gen | Produces | Volume |
|---|---|---|
| **G1 tool_gap** | Trajectory omitting an applicable tool | ~30,000 |
| **G2 technique_gap** | Trajectory omitting an applicable technique | ~40,000 |
| **G3 hallucination** | Ungrounded or contradicted finding assertions | ~25,000 |
| **G4 paired_contrast** | Same seed, one complete + one single-omission | ~15,000 pairs |

**G4 is the highest-value generator.** A controlled single-variable contrast
is exactly what forces a small model to attend to the difference rather than
to length or style. Pairs must be length-matched — pad the complete one with
plausible-but-irrelevant steps — or the model learns a length shortcut.

### S2 — Real agent trajectories (~1,500 records)

Harvested, normalised, then **filtered for contamination**. Candidates:

| Source | License | Use |
|---|---|---|
| `sammshen/intercode-minimax-traces` | MIT | Primary — small enough to inspect exhaustively |
| `antieval/cybergym-trajectories` | untagged | Verify license before use |
| AutoPenBench gold solutions | repo | **Negatives** — complete verified paths |

**Contamination filter is mandatory.** A published audit found **37.1% of
Cybench baseline passes involved cheating**, with scores inflated up to 5×
(arXiv:2607.21763). Their four-stage audit pipeline is reusable as our
filter; a trajectory that does not match a gold solution cannot serve as a
negative.

### S3 — CVE and writeup corpus (technique labels)

Sources, all with recorded license:

| Source | URL | License |
|---|---|---|
| CWE Top 25 (2025) | `cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html` | MITRE ToU |
| AutoPenBench milestones | `github.com/lucagioacchini/auto-pen-bench` | check |
| WSTG v4.2 | `github.com/OWASP/wstg` | CC BY-SA 4.0 |
| OWASP Top 10 (2025) | `owasp.org/Top10/2025/` | CC BY 3.0 |
| OWASP API Top 10 (2023) | `owasp.org/API-Security/editions/2023/` | verify |
| PortSwigger topics (30) | `portswigger.net/web-security/all-topics` | copyright, names only |

Two corrections baked in: ATT&CK Enterprise is **15 tactics** as of v19.2,
not the stale 14 (`Defense Evasion` split into `Stealth` + `Defense
Impairment`); and WSTG identifiers differ between v4.2 and v5.0, so **pin to
`WSTG-v42-*`**.

Taxonomy size is capped at ~15 technique labels rather than the ~200 a full
crosswalk yields. 200 labels is far beyond what a 5–20M scorer learns
reliably.

### S4 — Threat reporting and news (ATT&CK tactic labels)

Real intrusion narratives from vendor advisories and threat reports, mapped to
ATT&CK tactics. Purpose is coarse: *which phases of the kill chain did this
investigation never enter?*

⚠️ **Attribution claims are not ground truth.** Vendor reporting carries
known bias and contested attribution. Use these for tactic-level coverage
only, never as labels for technique-level claims. Strip speculation markers
(`believed`, `attributed to`, `suspected`) and drop records where the
attribution is the load-bearing claim.

### S5 — Logs (anomaly and technique signals)

Used for hallucination grounding — a claim is grounded when a log excerpt
supports it.

**Mandatory redaction before storage.** Raw security logs carry credentials,
session tokens, PII, and internal hostnames. Every record must pass
redaction for: bearer tokens, API keys, private keys, passwords in
connection strings, email addresses, and internal hostnames. Unredacted logs
do not enter the corpus, and the redactor is tested before generation starts.

### S6 — Real hallucination labels (~10,000 records)

The single most valuable real asset: **1,400 reviewer-validated invalid bug
bounty reports** plus ~8,500 grounded ones
(arXiv:2511.18608 — "From Reviewers' Lens"). Human reviewer labels, not
model labels, which makes them rare and high quality.

Note the paper's own finding: LLMs *"consistently struggle to detect invalid
cases, showing a tendency to over-accept."* That is our exact failure mode.

## What does not exist

State these plainly in any writeup:

1. ❌ No dataset of security-agent blind spots with ground truth.
2. ❌ No benchmark of hallucinated or fabricated CVE IDs — zero arXiv results.
   Fabrication is documented as a *mechanism* (stale knowledge causing
   knowledge conflict) and as anecdote (ten reviewers unanimously endorsing a
   non-existent Bleichenbacher oracle in OpenSSL CMS), never as labelled data.
3. ❌ No security-domain (claim, evidence) attribution dataset.
4. ❌ No structured corpus of "writeup where the author initially missed X" —
   such sentences exist in CTFtime writeups; nobody has extracted them.

## Negative-data rules

The most-skipped part of corpus construction, and skipping it is exactly how
a blind-spot scorer degenerates into "flag everything."

- **Published pentest reports are NOT valid negatives.** They are
  deliberately narrow — one finding, well-evidenced, minimal scope. Using
  them teaches the scorer that a thin report is fine.
- Valid negatives are **complete-trajectory**: an agent that worked through
  the applicable coverage set and stopped because there was nothing more.
  Sources: AutoPenBench gold solutions, InterCode successful runs,
  CTF-Dojo verified trajectories, the clean-pass subset of the cheating audit.
- Target ratio: **40% negatives**, hardcoded. Do not discover it empirically.

## Safety and handling constraints

These are not optional and are enforced by tests, not convention.

1. **Authorization framing.** Every record carries explicit authorization
   and sandbox context. Red-team data especially: over-refusal is the
   documented failure mode that makes security models operationally useless
   (CyberSecEval MITRE-FRR), so the framing belongs in the data from token
   one, not bolted on later.
2. **No live exploit payloads.** Technique labels and evidence structure
   only. We are training a *coverage auditor*, not a payload generator.
3. **Log redaction** before storage (S5).
4. **License recorded per record, card text not just the tag.** Known
   failures: `WhitzardAgent/CyberSecurity-1M` is tagged Apache-2.0 but its
   card says research-only; `CyberNative/CyberSecurityEval` carries a card
   citing unresolved provenance defects.
5. **Split by source document, never by row.** A random split leaks source
   text across the boundary and makes copy-rate return ~0 regardless of how
   much the model memorised.

## The real bottleneck

Not data volume — **the applicability function.** Deciding which techniques
*should* have been tried for a given target. Implemented in
`tinyforge/applicability.py`, deterministic and auditable, deliberately
biased toward under-flagging because false positives are the damaging error.

With 120k records and ~15 labels the head architecture is trivial. The
engineering effort belongs in applicability, not in data collection.