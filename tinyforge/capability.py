"""Host capability probe — decides which student this box can actually train.

The project has two students with very different requirements:

* **Student B** — ~20M params, from scratch, pure numpy. Needs roughly
  305 MiB of optimiser state (weights + grads + two Adam moments in fp32).
* **Student A** — SmolLM2-135M, LoRA SFT. Needs torch, and the closest
  published CPU measurement peaked at 2.18 GiB peak RSS.

Rather than guessing, probe the host and report the largest model that fits.
The probe is intentionally dependency-light: it reads /proc and /proc/cpuinfo
so it works before anything is installed.
"""

from __future__ import annotations

import os
import platform
import re
from dataclasses import dataclass, field
from typing import Optional

MIB = 1024 * 1024

# fp32 AdamW full-fine-tune footprint: weights (4) + grads (4) + m (4) + v (4)
# bytes per parameter. LoRA only pays optimiser state on the adapter, so the
# per-param figure is far lower — see ``lora_bytes_per_param``.
ADAMW_BYTES_PER_PARAM = 16
LORA_BYTES_PER_PARAM = 2.5

STUDENT_A = "smollm2-135m-lora"
STUDENT_B = "scratch-20m"


@dataclass
class CapabilityReport:
    """What this host can and cannot do."""

    cpu_model: str
    cpu_count: int
    total_ram_mib: int
    available_ram_mib: int
    swap_total_mib: int
    swap_free_mib: int
    disk_free_mib: int
    has_avx2: bool
    has_avx512: bool
    has_amx_bf16: bool
    has_torch: bool
    recommended: str
    feasible: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "cpu_model": self.cpu_model,
            "cpu_count": self.cpu_count,
            "total_ram_mib": self.total_ram_mib,
            "available_ram_mib": self.available_ram_mib,
            "swap_total_mib": self.swap_total_mib,
            "swap_free_mib": self.swap_free_mib,
            "disk_free_mib": self.disk_free_mib,
            "isa": {
                "avx2": self.has_avx2,
                "avx512": self.has_avx512,
                "amx_bf16": self.has_amx_bf16,
            },
            "has_torch": self.has_torch,
            "recommended": self.recommended,
            "feasible": list(self.feasible),
            "notes": list(self.notes),
        }

    def summary(self) -> str:
        lines = [
            f"cpu            {self.cpu_model} ({self.cpu_count} core)",
            f"ram            {self.total_ram_mib} MiB total / "
            f"{self.available_ram_mib} MiB available",
            f"swap           {self.swap_free_mib} MiB free of {self.swap_total_mib} MiB",
            f"disk free      {self.disk_free_mib} MiB",
            f"isa            avx2={self.has_avx2} avx512={self.has_avx512} "
            f"amx_bf16={self.has_amx_bf16}",
            f"torch          {'present' if self.has_torch else 'absent'}",
            f"recommended    {self.recommended}",
            f"feasible       {', '.join(self.feasible) or 'none'}",
        ]
        lines.extend(f"note           {n}" for n in self.notes)
        return "\n".join(lines)


def _read_meminfo() -> tuple[int, int, int, int]:
    """Return (total_mib, available_mib, swap_total_mib, swap_free_mib)."""
    values: dict[str, int] = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if parts and parts[0].isdigit():
                    values[key] = int(parts[0]) // 1024
    except OSError:
        return 0, 0, 0, 0
    return (
        values.get("MemTotal", 0),
        values.get("MemAvailable", 0),
        values.get("SwapTotal", 0),
        values.get("SwapFree", 0),
    )


def _read_cpu() -> tuple[str, int, bool, bool, bool]:
    """Return (model, cores, avx2, avx512, amx_bf16)."""
    model = platform.processor() or "unknown"
    cores = os.cpu_count() or 1
    flags: set[str] = set()
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                elif line.startswith("flags"):
                    flags = set(line.split(":", 1)[1].split())
                    break
    except OSError:
        pass
    return (
        model,
        cores,
        "avx2" in flags,
        "avx512f" in flags,
        "amx_bf16" in flags or "avx512_bf16" in flags,
    )


def _read_disk_free_mib(path: str = "/") -> int:
    try:
        st = os.statvfs(path)
        return (st.f_bavail * st.f_frsize) // MIB
    except OSError:
        return 0


def _has_torch() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("torch") is not None
    except (ImportError, ValueError):
        return False


def estimate_budget_mib(params: int, *, bytes_per_param: int = ADAMW_BYTES_PER_PARAM,
                        activation_reserve_mib: int = 192) -> int:
    """Estimated peak RSS in MiB for a full fine-tune of *params*."""
    return (params * bytes_per_param) // MIB + activation_reserve_mib


def probe(*, headroom_mib: int = 96) -> CapabilityReport:
    """Inspect the host and pick the largest feasible student.

    *headroom_mib* is the slice of RAM deliberately withheld from the model
    so the rest of the box (editor, this process, the page cache) survives.
    """
    model, cores, avx2, avx512, amx = _read_cpu()
    total, avail, swap_total, swap_free = _read_meminfo()
    disk_free = _read_disk_free_mib()
    torch_present = _has_torch()

    notes: list[str] = []

    # Budget = available RAM plus whatever swap is free, minus headroom.
    budget = avail + swap_free - headroom_mib
    if budget < 0:
        notes.append(
            f"memory budget is negative ({budget} MiB): this host cannot train "
            "any student without freeing RAM first"
        )
        budget = 0

    feasible: list[str] = []
    if estimate_budget_mib(20_000_000) <= budget:
        feasible.append(STUDENT_B)
    else:
        notes.append(
            f"Student B needs ~{estimate_budget_mib(20_000_000)} MiB but only "
            f"{budget} MiB is available"
        )

    # Student A: published CPU LoRA peak was 2.18 GiB. Require that plus
    # torch, otherwise it is not something this host can do.
    student_a_mib = 2232
    if student_a_mib <= budget:
        if torch_present:
            feasible.append(STUDENT_A)
        else:
            notes.append(
                f"Student A would fit in {budget} MiB but torch is not "
                "installed (a CPU wheel is a ~170 MiB download)"
            )
    else:
        notes.append(
            f"Student A needs ~{student_a_mib} MiB (published CPU LoRA peak "
            f"was 2.18 GiB) but only {budget} MiB is available"
        )

    if not avx2:
        notes.append(
            "no AVX2: expect a large throughput penalty and re-verify all "
            "timing estimates before trusting them"
        )
    if avx512 or amx:
        notes.append(
            "AVX-512/AMX present: benchmark bf16 against fp32 before "
            "committing to a dtype"
        )
    else:
        notes.append(
            "no AVX-512/AMX: use fp32. bf16 upconverts on this ISA and gives "
            "fp32 throughput with worse numerics"
        )
    if cores == 1:
        notes.append(
            "single core: expect roughly 10-30 GFLOP/s fp32; pretraining from "
            "scratch is not viable (a 135M model needs ~5 years here)"
        )
    if disk_free < 2048:
        notes.append(
            f"only {disk_free} MiB disk free: a corpus and checkpoints will "
            "not fit without further cleanup"
        )

    if feasible:
        recommended = STUDENT_A if STUDENT_A in feasible else STUDENT_B
    else:
        recommended = "none"

    return CapabilityReport(
        cpu_model=model,
        cpu_count=cores,
        total_ram_mib=total,
        available_ram_mib=avail,
        swap_total_mib=swap_total,
        swap_free_mib=swap_free,
        disk_free_mib=disk_free,
        has_avx2=avx2,
        has_avx512=avx512,
        has_amx_bf16=amx,
        has_torch=torch_present,
        recommended=recommended,
        feasible=tuple(feasible),
        notes=tuple(notes),
    )