"""tinyforge — CPU-only tiny-model training and evaluation for security work.

Scope: everything here runs on a single CPU core with no GPU. The
from-scratch student has no torch dependency at all; the LoRA student is
gated on host capability by :func:`tinyforge.capability.probe`.

The project builds a **small scorer that sits beneath a large model** rather
than a standalone assistant: it assigns scores, ranks candidates, and makes
binary decisions while a frontier model does all generation. See DESIGN.md.
"""

from .capability import CapabilityReport, probe

__all__ = ["CapabilityReport", "probe"]