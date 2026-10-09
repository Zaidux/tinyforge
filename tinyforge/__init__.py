"""tinyforge — CPU-only tiny-model training and evaluation for security work.

Scope: everything here runs on a single CPU core with no GPU. The
from-scratch student has no torch dependency at all; the LoRA student is
gated on host capability by :func:`tinyforge.capability.probe`.
"""

from .capability import CapabilityReport, probe

__all__ = ["CapabilityReport", "probe"]