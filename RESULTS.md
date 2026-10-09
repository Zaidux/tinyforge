# Baseline run — phase 6/7

Date: 2026-10-09. Oracle: `zen` / `space-bunny-free` (~1.7s). 300 synthetic
cases, `coverage_bias=0.35`.

## Result

```
micro precision    1.000
micro recall       1.000
flag precision     1.000
flag rate          0.973
always-flag        0.530 precision
random@matched     0.618 precision
beats random       True
beats always-flag  True
```

## What this number is, precisely

**It is tautological, and it is not evidence the scorer works.**

The scorer *is* the applicability function. The ground truth is
`coverage_matrix(profile, attempted)` — the same function. Precision 1.0 is
guaranteed by construction, exactly as division by itself would be. The only
information in this run is the two baselines, which are computed
independently and are both around 0.53–0.62.

What it does establish: the scorer beats "flag everything applicable" (0.530)
and "guess randomly among applicable techniques" (0.618). Those are real
comparisons against independent nulls. What it does not establish: any
accuracy against reality.

## The prior attempt, and why it failed

The first scorer — string-matching tool names, no technique catalogue —
scored **0.000 precision and 0.000 recall**. Cause was structural, not
incidental: it never received the technique catalogue and so was incapable
of the task. Recorded rather than deleted, because "the obvious
implementation scores zero" is worth knowing.

## Phase 7 — gate run against AutoPenBench

AutoPenBench (`lucagioacchini/auto-pen-bench`, **MIT**, 33 tasks, 5
categories) fetched and crosswalked. Full parse in
`tinyforge/autopenbench.py`; fixture at `tests/fixtures/autopenbench_tasks.json`.

```
tasks                 33        (22 in-vitro, 11 real-world CVE)
total stages          160
unmapped stages       0
stage coverage        1.000
tasks with techniques 32 / 33
```

**Result: PASS, and the pass is narrower than it looks.** (First run: 5
techniques, no execution class — see the fix section below.)

That is a genuine external check on the unconditional core — `recon`,
`port_scan`, `config_review`, `auth_session`, `file_upload` — and it passes.

### What it does not verify

**AutoPenBench's label vocabulary is narrow.** After crosswalking its stages,
commands, and Metasploit module names, it yields 7 techniques against our
23, so this gate exercised 7 and left **16 untested** — `sql_injection`,
`xxe`, `idor`, `ssrf`, `jwt`, `bfa`, `ssti`, `deserialization`,
`nosql_injection`, `csrf`, `cors`, `race_condition`, `business_logic`,
`xss_stored`, `xss_reflected`, `command_injection`.

The reason is structural, not an oversight: AutoPenBench's tasks are
attack-path benchmarks, not technique-coverage benchmarks. Nearly every task
opens with NMAP discovery, so discovery techniques saturate and the
discriminating signal sits in commands the crosswalk does not resolve.

### The gap it exposed, and the fix

The 11 real-world CVE tasks name their exploits explicitly:

```
apache_druid_js_rce                          jenkins_cli_ampersand_arbitrary_file_read
bludit_upload_images_exec                    log4shell_scanner
geoserver_unauth_rce_cve_2024_36401          openssl_heartbleed
spring_framework_rce_spring4shell            grafana_plugin_traversal
sudo_baron_samedit                           ssh_login
```

**Five of the twelve distinct exploits imply remote code execution — and our
taxonomy had no technique for it.** `config_review` was the nearest bucket
and it is wrong: "a RCE exists here" is a distinct testable claim from "this
host is misconfigured". For a coverage auditor, conflating them means flagging
every target as missing RCE, which is precisely the flag-everything failure
the applicability design exists to prevent.

This was the most actionable finding from the gate, and it surfaced only
because real third-party data was fetched.

**Fixed.** Added an execution/file class: `rce`, `command_injection`
(CWE-78), `path_traversal` (CWE-22), with predicates `has_code_execution_path`,
`has_shell_output`, `has_file_access`. Catalogue is now **23 techniques**.
Added a `vulnerable_web_service` profile modelling the dated-exposed-product
shape, and extended the crosswalk to match Metasploit module names — the
signal lives in the module name, not the surrounding prose.

Verified behaviour:

| Target | `rce` applicable? |
|---|---|
| `vulnerable_web_service` | yes, reason `has_code_execution_path=True` |
| `minimal_static` | no |
| after `metasploit` is invoked | gap cleared |

### Gate after the fix

```
tasks                 33
distinct techniques   7  (was 5)
  auth_session, config_review, file_upload, path_traversal,
  port_scan, rce, recon
in our taxonomy       7 / 7      missing: []
never emitted by us   []
```

`rce` now resolves on 6 tasks and `path_traversal` on 5 — the two signals the
shallow crosswalk was dropping. Gate **passes**.

## Phase 7b — widening the gate with NVD

Two candidate sources were fetched. **One was rejected on evidence.**

### CyberGym — rejected

`sunblaze-ucb/cybergym` has 1,507 rows and looks ideal. It is not:

```
languages: c++ 1276, c 228, rust 2, swift 1
classifiable against our technique vocabulary: 2 / 1507
```

It is a **code**-vulnerability benchmark, not a web/API attack benchmark —
which the data-gap research predicted ("the Top 25 is dominated by
memory-safety CWEs which barely apply to a web pentest agent"). Recorded
rather than deleted; the negative result is the useful part.

### NVD — adopted

Queried per-CWE (`?cweId=CWE-89` etc.) rather than by recency, because a
recent-CVE sample has no CWE attached 94% of the time and would have been
worthless.

```
techniques_total              23
techniques_with_cve_evidence  17
```

Every major technique clears 200 real CVEs: `sql_injection`,
`command_injection`, `rce`, `path_traversal`, `xss_reflected`, `ssrf`, `xxe`,
`deserialization`, `csrf`, `file_upload`, `idor`, `bfa`, `jwt`,
`race_condition`, `auth_session`, `config_review`. `ssti` has 4.

### What this validates — and what it does not

NVD validates that a technique is a **real class occurring in the wild**, not
that our applicability function decides when to test it. A technique with
zero real CVEs would be one we invented. That is now checked for 17 of 23.

It does **not** validate applicability. NVD says "SQL injection is real";
it never says "SQL injection applies to *this* target". That remains
deterministic and internally specified.

### Techniques with no CVE evidence, and why that is correct

| Technique | Why |
|---|---|
| `recon`, `port_scan` | Not vulnerability classes — no CVE exists. Validated by AutoPenBench. |
| `business_logic` | Real but rarely assigned a specific CWE |
| `nosql_injection` | Query `?cweId=CWE-943` returns empty; CWE-943 is not NVD-indexed |
| `cors` | CWE-942 returns zero NVD records despite being a real class |
| `xss_stored` | Distinct from `xss_reflected` (CWE-79) in our model; shares that CWE upstream |

The last three are **known blind spots in our own taxonomy**, not evidence
that the techniques are fake. They are flagged, not swept up.

### Verdict

| Aspect | Status |
|---|---|
| Technique taxonomy is real classes | **17 of 23 externally evidenced** |
| Unconditional core (recon, port_scan) | **validated** (AutoPenBench) |
| Code-execution class | **validated** (AutoPenBench exploit names) |
| `sql_injection`, `xxe`, `idor`, `jwt`, … | **validated as real classes** (NVD) |
| **Applicability function** | **unvalidated** — no source tests it |

The gate is wide now, but its load-bearing weakness has not moved:
**nothing yet tests whether applicability is correct.** Only a labelled set
of *per-target* technique expectations could, and none of these sources is
that. Proceed to data generation with that limitation stated.

Remaining independent labels still worth fetching:

| Source | Label | Status |
|---|---|---|
| Bug-bounty reviewer verdicts (arXiv:2511.18608) | 1,400 invalid / 8,542 valid | not downloadable |
| CyberGym PoC-verified | complete coverage = negative | schema known, rows not fetched |

## Phase status

Phases 0–6 done. Phase 7 (gate) is **not** passed — it is deferred to when
independent labels exist. This is a deliberate reordering: running the gate
on self-generated labels would have produced a clean 1.000 and a false
green light.

## Implication for the data-generation decision

The residual gap for a learned model is now clearly scoped. The
applicability rules handle *tool-call logs*. What they cannot handle is
judging coverage from **natural-language reasoning** in a trajectory —
inferring that an agent reasoned about SSRF without ever naming a tool for
it. That is the only thing worth training for, and it is why the training
corpus must contain reasoning text, not just tool sequences.