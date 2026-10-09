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
distinct techniques   auth_session, config_review, file_upload,
                      port_scan, recon
```

**Result: PASS, but the pass is much weaker than it looks.**

### What it actually verifies

All five techniques AutoPenBench's labels resolve to **exist in our
taxonomy**, and **none of them are ones our profiles fail to emit**:

```
third-party techniques: 5
present in our taxonomy: 5/5
missing from ours:      []
never emitted by us:    []
```

That is a genuine external check on the unconditional core — `recon`,
`port_scan`, `config_review`, `auth_session`, `file_upload` — and it passes.

### What it does not verify

**AutoPenBench's label vocabulary is only five techniques wide.** After
crosswalking its stages and commands, that is all the technique signal it
yields. Our taxonomy has 19. So this gate exercised **5 of 19** techniques
and left **14 entirely untested** — every conditional one (`sql_injection`,
`xxe`, `idor`, `ssrf`, `jwt`, `bfa`, `file_upload` edge cases, …).

The reason is structural, not an oversight: AutoPenBench's tasks are
attack-path benchmarks, not technique-coverage benchmarks. Nearly every task
opens with NMAP discovery, so discovery techniques saturate and the
discriminating signal sits in commands the crosswalk does not resolve.

### The gap it did expose

The 11 real-world CVE tasks name their exploits explicitly:

```
apache_druid_js_rce                          jenkins_cli_ampersand_arbitrary_file_read
bludit_upload_images_exec                    log4shell_scanner
geoserver_unauth_rce_cve_2024_36401          openssl_heartbleed
spring_framework_rce_spring4shell            grafana_plugin_traversal
sudo_baron_samedit                           ssh_login
```

**Five of the twelve distinct exploits imply remote code execution — and our
taxonomy has no technique for it.** `config_review` is the nearest bucket
and it is wrong: "a RCE exists here" is a distinct testable claim from "this
host is misconfigured". For a coverage auditor, conflating them means
flagging every target as missing RCE, which is precisely the
flag-everything failure the applicability design exists to prevent.

This is the most actionable finding from the gate, and it came only from
fetching real third-party data. Add an `rce`-class technique before the
training corpus is generated, or every CVE-bearing target generates a
systematic false positive.

### Verdict

The unconditional core is externally validated. The conditional half of the
taxonomy is **unvalidated**, and the RCE gap is a known defect. Gate passes
for proceeding to data generation, conditional on fixing the RCE class.

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