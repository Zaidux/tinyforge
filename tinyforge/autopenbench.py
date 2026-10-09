"""AutoPenBench milestone loader — third-party technique-coverage ground truth.

## Why this source

The data-gap analysis established that no dataset of security-agent blind
spots with ground truth exists. AutoPenBench is the closest published
artifact: per-task ``command_milestones`` and ``stage_milestones`` files
defining an ordered expected attack path, authored by third parties.

That matters for a specific reason. The applicability function's own
evaluation was **tautological** — the scorer is the applicability function
and the ground truth was derived from it, so precision was 1.000 by
construction. Only labels authored independently of our code can settle
whether applicability is actually correct.

## What it gives

* 33 tasks across 5 categories (22 in-vitro, 11 real-world CVE)
* ``command_milestones`` — natural-language descriptions of required
  commands, which is the reasoning text the training corpus needs and that
  tool-call logs cannot supply
* ``stage_milestones`` — a coarse 13-stage attack-path taxonomy

## Licensing

MIT (`lucagioacchini/auto-pen-bench`). Fetched at runtime, never vendored,
so the repository does not redistribute third-party content.

## The mapping problem, stated honestly

AutoPenBench describes *stages and commands*; our taxonomy describes
*techniques*. Converting between them requires a keyword crosswalk, and a
keyword crosswalk is lossy. The `map_stages_to_techniques` function
therefore reports what it matched rather than pretending to a clean
equivalence, and :func:`crosswalk_coverage` measures agreement so the
quality of the mapping is visible instead of assumed.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, Sequence

__all__ = [
    "AutoPenTask",
    "fetch_tree",
    "fetch_raw",
    "load_tasks",
    "parse_stage_milestones",
    "parse_command_milestones",
    "map_stages_to_techniques",
    "crosswalk_coverage",
    "REPO",
    "BRANCH",
]

REPO = "lucagioacchini/auto-pen-bench"
BRANCH = "main"
_UA = {"User-Agent": "tinyforge"}


@dataclass
class AutoPenTask:
    """One benchmark task with its third-party labels."""

    task_id: str
    category: str
    kind: str  # "in-vitro" | "real-world"
    #: Ordered attack stages, e.g. ["Target Discovery", "Exploitation"].
    stages: tuple[str, ...] = ()
    #: Natural-language required commands.
    commands: tuple[str, ...] = ()
    #: Techniques the crosswalk attributed to this task.
    techniques: tuple[str, ...] = ()
    #: Where the crosswalk had nothing to match.
    unmapped_stages: tuple[str, ...] = ()
    source_url: str = ""

    def as_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "category": self.category,
            "kind": self.kind,
            "stages": list(self.stages),
            "commands": list(self.commands),
            "techniques": list(self.techniques),
            "unmapped_stages": list(self.unmapped_stages),
            "source_url": self.source_url,
        }


def _get_json(url: str):
    req = urllib.request.Request(url, headers={**_UA, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=40) as fh:
        return json.load(fh)


def fetch_tree(repo: str = REPO, branch: str = BRANCH) -> list[str]:
    """Return every blob path in the repository."""
    data = _get_json(
        f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
    )
    if data.get("truncated"):
        raise RuntimeError("tree truncated; repository larger than expected")
    return [t["path"] for t in data["tree"] if t["type"] == "blob"]


def fetch_raw(path: str, repo: str = REPO, branch: str = BRANCH) -> str:
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=25) as fh:
        return fh.read().decode("utf-8", "replace")


def parse_stage_milestones(text: str) -> tuple[tuple[str, ...], dict[str, int]]:
    """Parse ``Stage Name,command_index`` lines.

    Returns the stage names in file order plus the index map, which encodes
    the ordering of the expected attack path.
    """
    stages: list[str] = []
    index: dict[str, int] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        name, _, idx = line.rpartition(",")
        name = name.strip()
        try:
            index[name] = int(idx.strip())
        except ValueError:
            continue
        stages.append(name)
    return tuple(stages), index


def parse_command_milestones(text: str) -> tuple[str, ...]:
    """Parse the required-command descriptions, dropping blanks."""
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            out.append(line)
    return tuple(out)


#: Stage -> technique crosswalk. Explicit and inspectable rather than a
#: fuzzy match, because a crosswalk nobody can audit is a crosswalk nobody
#: should trust. Keys are matched case-insensitively against stage names and
#: against command text.
STAGE_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "target discovery": ("recon", "port_scan"),
    "reconnaissance": ("recon", "port_scan"),
    "identification": ("recon",),
    "target infiltration": ("config_review",),
    "vulnerability detection": ("config_review",),
    "vulnerability discovery": ("config_review",),
    "exploitation": (),  # stage-level; technique comes from the commands
    "vulnerability exploitation": (),
    "exploit development": (),
    "exploit execution": (),
    "privilege escalation": (),
    "flag capturing": (),
    "success": (),
}

#: Command-text keywords -> technique. This is where the real signal lives:
#: "Use SQLMAP to test for SQL injection" is a technique label written in
#: English by a third party.
COMMAND_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "sqlmap": ("sql_injection",),
    "sql injection": ("sql_injection",),
    "nmap": ("port_scan",),
    "port scan": ("port_scan",),
    "nikto": ("config_review",),
    "nuclei": ("config_review",),
    "ffuf": ("sql_injection",),
    "gobuster": ("config_review",),
    "dirb": ("config_review",),
    "curl": ("config_review",),
    "hydra": ("auth_session",),
    "john": ("auth_session",),
    "hashcat": ("auth_session",),
    "metasploit": ("config_review",),
    "burp": ("xss_reflected",),
    "passwd": ("file_upload",),
    "/etc/passwd": ("file_upload",),
    "flag.txt": (),
}


#: Metasploit module names -> techniques. This is where the code-execution
#: class was found: the real-world CVE tasks name their exploits, and five
#: of twelve imply RCE. Keyword-matching the command text alone missed them
#: because the signal lives in the module name, not the surrounding prose.
EXPLOIT_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "geoserver_unauth_rce": ("rce",),
    "spring_framework_rce": ("rce",),
    "spring4shell": ("rce",),
    "apache_druid_js_rce": ("rce",),
    "bludit_upload_images_exec": ("rce",),
    "log4shell": ("rce",),
    "apache_normalize_path": ("path_traversal",),
    "grafana_plugin_traversal": ("path_traversal",),
    "jenkins_cli_ampersand_arbitrary_file_read": ("path_traversal",),
    "arbitrary_file_read": ("path_traversal",),
    "sudo_baron_samedit": ("rce",),
    "openssl_heartbleed": ("path_traversal",),
    "ssh_login": ("auth_session",),
    "is_known_pipename": ("path_traversal",),
}


def map_stages_to_techniques(
    stages: Sequence[str], commands: Sequence[str]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Crosswalk third-party labels onto our technique ids.

    Returns ``(techniques, unmapped_stages)``. ``unmapped_stages`` is
    non-empty for stages the crosswalk does not cover — surfacing that is
    the point, because a silent mapping would let a partial crosswalk look
    complete.
    """
    found: list[str] = []
    unmapped: list[str] = []

    for stage in stages:
        key = stage.strip().lower()
        mapped = STAGE_TECHNIQUES.get(key)
        if mapped is None:
            unmapped.append(stage)
        else:
            found.extend(mapped)

    for command in commands:
        lowered = command.lower()
        for needle, techs in COMMAND_TECHNIQUES.items():
            if needle in lowered:
                found.extend(techs)
        for module, techs in EXPLOIT_TECHNIQUES.items():
            if module in lowered:
                found.extend(techs)

    return tuple(dict.fromkeys(found)), tuple(unmapped)


def load_tasks(repo: str = REPO, branch: str = BRANCH) -> list[AutoPenTask]:
    """Fetch and parse every task with both milestone files."""
    paths = fetch_tree(repo, branch)
    base = f"https://github.com/{repo}/tree/{branch}/"
    tasks: list[AutoPenTask] = []

    for path in sorted(p for p in paths if "command_milestones" in p):
        parts = path.split("/")
        # .../command_milestones/<kind>/<category>/<vm>.txt
        kind, category, fname = parts[-3], parts[-2], parts[-1]
        task_id = f"{kind}/{category}/{fname[:-4]}"

        commands = parse_command_milestones(fetch_raw(path, repo, branch))

        stages: tuple[str, ...] = ()
        stage_path = path.replace("command_milestones", "stage_milestones")
        try:
            stages, _ = parse_stage_milestones(fetch_raw(stage_path, repo, branch))
        except urllib.error.HTTPError:
            pass

        techniques, unmapped = map_stages_to_techniques(stages, commands)
        tasks.append(
            AutoPenTask(
                task_id=task_id,
                category=category,
                kind=kind,
                stages=stages,
                commands=commands,
                techniques=techniques,
                unmapped_stages=unmapped,
                source_url=base + path,
            )
        )
    return tasks


def crosswalk_coverage(tasks: Iterable[AutoPenTask]) -> dict:
    """Report how much of the third-party labelling we actually captured.

    A crosswalk that silently drops half the stages would otherwise look
    identical to one that captured everything.

    Accepts either :class:`AutoPenTask` instances or the plain dicts written
    by :func:`capture_fixture`, so the report can be recomputed offline from
    the captured fixture without a network round-trip.
    """
    tasks = list(tasks)
    total_stages = 0
    unmapped = 0
    with_tech = 0
    techniques: set[str] = set()
    for t in tasks:
        if isinstance(t, AutoPenTask):
            total_stages += len(t.stages)
            unmapped += len(t.unmapped_stages)
            if t.techniques:
                with_tech += 1
            techniques.update(t.techniques)
        else:
            total_stages += len(t.get("stages", ()))
            unmapped += len(t.get("unmapped_stages", ()))
            if t.get("techniques"):
                with_tech += 1
            techniques.update(t.get("techniques", ()))
    return {
        "tasks": len(tasks),
        "total_stages": total_stages,
        "unmapped_stages": unmapped,
        "stage_coverage": round(1 - unmapped / total_stages, 4) if total_stages else 0.0,
        "tasks_with_techniques": with_tech,
        "technique_coverage": round(with_tech / len(tasks), 4) if tasks else 0.0,
        "distinct_techniques": sorted(techniques),
    }