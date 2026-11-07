"""Shared helpers: fixture paths."""

from __future__ import annotations

import sys
from pathlib import Path

# Flat package layout: soc_mini_lab/ is in the repo root, not under src/.
sys.path.insert(0, str(Path(__file__).parent.parent))

FIXTURES = Path(__file__).parent / "fixtures"
