# Applicability annotation form

Annotator: `(fill in)`

For each technique, answer whether it **applies to this target**.

This is about whether the test is *warranted*, not whether the target
is vulnerable. A target with no SQL injection still needs an SQL
injection test.

Responses: `yes` / `no` / `unsure`. Cite the observable fact that drove
your answer. `unsure` is a real answer — use it rather than guessing.

Our function's prediction is deliberately not shown. Fill this in
before looking at any prediction.

## js-full — juice-shop / whole-app

**Observed facts:** `{"accepts_xml": true, "has_code_execution_path": true, "has_deserialization": true, "has_login": true, "has_object_ids": true, "has_relational_db": true, "has_templating": true, "has_upload": true, "uses_jwt": true, "uses_nosql": true}`

**App author's documented techniques:** auth_session, bfa, config_review, deserialization, idor, jwt, nosql_injection, rce, sql_injection, xss_reflected, xss_stored, xxe

| technique | applies? | observed fact cited | notes |
|---|---|---|---|
| `recon` — Subdomain and endpoint discovery | ☐ yes ☐ no ☐ unsure |  |  |
| `port_scan` — Service and port discovery | ☐ yes ☐ no ☐ unsure |  |  |
| `config_review` — Security misconfiguration review | ☐ yes ☐ no ☐ unsure |  |  |
| `auth_session` — Authentication and session handling | ☐ yes ☐ no ☐ unsure |  |  |
| `sql_injection` — SQL injection | ☐ yes ☐ no ☐ unsure |  |  |
| `nosql_injection` — NoSQL injection | ☐ yes ☐ no ☐ unsure |  |  |
| `xss_reflected` — Reflected XSS | ☐ yes ☐ no ☐ unsure |  |  |
| `xss_stored` — Stored XSS | ☐ yes ☐ no ☐ unsure |  |  |
| `ssrf` — Server-side request forgery | ☐ yes ☐ no ☐ unsure |  |  |
| `xxe` — XML external entity processing | ☐ yes ☐ no ☐ unsure |  |  |
| `csrf` — Cross-site request forgery | ☐ yes ☐ no ☐ unsure |  |  |
| `idor` — Insecure direct object reference | ☐ yes ☐ no ☐ unsure |  |  |
| `bfa` — Broken function-level authorization | ☐ yes ☐ no ☐ unsure |  |  |
| `file_upload` — Unrestricted file upload | ☐ yes ☐ no ☐ unsure |  |  |
| `ssti` — Server-side template injection | ☐ yes ☐ no ☐ unsure |  |  |
| `deserialization` — Unsafe deserialization | ☐ yes ☐ no ☐ unsure |  |  |
| `jwt` — JWT handling weaknesses | ☐ yes ☐ no ☐ unsure |  |  |
| `cors` — CORS misconfiguration | ☐ yes ☐ no ☐ unsure |  |  |
| `race_condition` — Race conditions | ☐ yes ☐ no ☐ unsure |  |  |
| `business_logic` — Business logic flaws | ☐ yes ☐ no ☐ unsure |  |  |
| `command_injection` — OS command injection | ☐ yes ☐ no ☐ unsure |  |  |
| `rce` — Remote code execution | ☐ yes ☐ no ☐ unsure |  |  |
| `path_traversal` — Path traversal / arbitrary file read | ☐ yes ☐ no ☐ unsure |  |  |

## js-api — juice-shop / rest-api

**Observed facts:** `{"has_login": true, "has_object_ids": true, "has_upload": true}`

**App author's documented techniques:** auth_session, jwt, idor, bfa, sql_injection, nosql_injection

| technique | applies? | observed fact cited | notes |
|---|---|---|---|
| `recon` — Subdomain and endpoint discovery | ☐ yes ☐ no ☐ unsure |  |  |
| `port_scan` — Service and port discovery | ☐ yes ☐ no ☐ unsure |  |  |
| `config_review` — Security misconfiguration review | ☐ yes ☐ no ☐ unsure |  |  |
| `auth_session` — Authentication and session handling | ☐ yes ☐ no ☐ unsure |  |  |
| `sql_injection` — SQL injection | ☐ yes ☐ no ☐ unsure |  |  |
| `nosql_injection` — NoSQL injection | ☐ yes ☐ no ☐ unsure |  |  |
| `xss_reflected` — Reflected XSS | ☐ yes ☐ no ☐ unsure |  |  |
| `xss_stored` — Stored XSS | ☐ yes ☐ no ☐ unsure |  |  |
| `ssrf` — Server-side request forgery | ☐ yes ☐ no ☐ unsure |  |  |
| `xxe` — XML external entity processing | ☐ yes ☐ no ☐ unsure |  |  |
| `csrf` — Cross-site request forgery | ☐ yes ☐ no ☐ unsure |  |  |
| `idor` — Insecure direct object reference | ☐ yes ☐ no ☐ unsure |  |  |
| `bfa` — Broken function-level authorization | ☐ yes ☐ no ☐ unsure |  |  |
| `file_upload` — Unrestricted file upload | ☐ yes ☐ no ☐ unsure |  |  |
| `ssti` — Server-side template injection | ☐ yes ☐ no ☐ unsure |  |  |
| `deserialization` — Unsafe deserialization | ☐ yes ☐ no ☐ unsure |  |  |
| `jwt` — JWT handling weaknesses | ☐ yes ☐ no ☐ unsure |  |  |
| `cors` — CORS misconfiguration | ☐ yes ☐ no ☐ unsure |  |  |
| `race_condition` — Race conditions | ☐ yes ☐ no ☐ unsure |  |  |
| `business_logic` — Business logic flaws | ☐ yes ☐ no ☐ unsure |  |  |
| `command_injection` — OS command injection | ☐ yes ☐ no ☐ unsure |  |  |
| `rce` — Remote code execution | ☐ yes ☐ no ☐ unsure |  |  |
| `path_traversal` — Path traversal / arbitrary file read | ☐ yes ☐ no ☐ unsure |  |  |

## js-upload — juice-shop / file-and-xml

**Observed facts:** `{"accepts_xml": true, "has_code_execution_path": true, "has_deserialization": true, "has_relational_db": true, "has_templating": true, "has_upload": true, "uses_jwt": true, "uses_nosql": true}`

**App author's documented techniques:** file_upload, xxe, deserialization, rce, path_traversal, ssti

| technique | applies? | observed fact cited | notes |
|---|---|---|---|
| `recon` — Subdomain and endpoint discovery | ☐ yes ☐ no ☐ unsure |  |  |
| `port_scan` — Service and port discovery | ☐ yes ☐ no ☐ unsure |  |  |
| `config_review` — Security misconfiguration review | ☐ yes ☐ no ☐ unsure |  |  |
| `auth_session` — Authentication and session handling | ☐ yes ☐ no ☐ unsure |  |  |
| `sql_injection` — SQL injection | ☐ yes ☐ no ☐ unsure |  |  |
| `nosql_injection` — NoSQL injection | ☐ yes ☐ no ☐ unsure |  |  |
| `xss_reflected` — Reflected XSS | ☐ yes ☐ no ☐ unsure |  |  |
| `xss_stored` — Stored XSS | ☐ yes ☐ no ☐ unsure |  |  |
| `ssrf` — Server-side request forgery | ☐ yes ☐ no ☐ unsure |  |  |
| `xxe` — XML external entity processing | ☐ yes ☐ no ☐ unsure |  |  |
| `csrf` — Cross-site request forgery | ☐ yes ☐ no ☐ unsure |  |  |
| `idor` — Insecure direct object reference | ☐ yes ☐ no ☐ unsure |  |  |
| `bfa` — Broken function-level authorization | ☐ yes ☐ no ☐ unsure |  |  |
| `file_upload` — Unrestricted file upload | ☐ yes ☐ no ☐ unsure |  |  |
| `ssti` — Server-side template injection | ☐ yes ☐ no ☐ unsure |  |  |
| `deserialization` — Unsafe deserialization | ☐ yes ☐ no ☐ unsure |  |  |
| `jwt` — JWT handling weaknesses | ☐ yes ☐ no ☐ unsure |  |  |
| `cors` — CORS misconfiguration | ☐ yes ☐ no ☐ unsure |  |  |
| `race_condition` — Race conditions | ☐ yes ☐ no ☐ unsure |  |  |
| `business_logic` — Business logic flaws | ☐ yes ☐ no ☐ unsure |  |  |
| `command_injection` — OS command injection | ☐ yes ☐ no ☐ unsure |  |  |
| `rce` — Remote code execution | ☐ yes ☐ no ☐ unsure |  |  |
| `path_traversal` — Path traversal / arbitrary file read | ☐ yes ☐ no ☐ unsure |  |  |

---

When finished, save to `annotations/judgements_<annotator>.json`.

```json
[
  {
    "target_id": "...",
    "technique": "...",
    "annotator": "...",
    "response": "yes|no|unsure",
    "rationale": "...",
    "cited_evidence": "..."
  }
]
```