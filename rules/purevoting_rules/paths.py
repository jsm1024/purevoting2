from __future__ import annotations

import os
from pathlib import Path


def reference_root() -> Path:
    """Use monorepo contracts when integrated; bundled references when standalone."""
    override = os.environ.get("PUREVOTING_REFERENCE_ROOT")
    if override:
        path = Path(override).expanduser().resolve()
        if not (path / "contracts/finding.schema.json").is_file():
            raise FileNotFoundError("PUREVOTING_REFERENCE_ROOT lacks contracts/finding.schema.json")
        return path
    parent = Path(__file__).resolve().parents[2]
    for candidate in (parent, parent / "reference"):
        if (candidate / "contracts/finding.schema.json").is_file():
            return candidate
    raise FileNotFoundError("Run inside the package or PureVoting monorepo; frozen contracts were not found")
