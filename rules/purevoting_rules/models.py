from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RuleOutcome:
    """Rule decision plus implementation coverage, before finding metadata.

    Coverage belongs to the development report. It is not a new frozen API field.
    A partially implemented rule must never return PASS.
    """

    rule_id: str
    result: str
    observed: dict[str, Any]
    expected: str
    summary: str
    evidence_refs: list[dict[str, str]] = field(default_factory=list)
    inconclusive_reason: str | None = None
    coverage: str = "complete"
    unimplemented_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.rule_id not in {"R1", "R2", "R3", "R4", "R5"}:
            raise ValueError("Unknown rule ID")
        if self.result not in {"PASS", "FAIL", "INCONCLUSIVE"}:
            raise ValueError("Unknown rule result")
        if self.coverage not in {"complete", "partial"}:
            raise ValueError("Unknown implementation coverage")
        if self.coverage == "partial" and self.result == "PASS":
            raise ValueError("A partially implemented rule cannot return PASS")
        if self.result == "INCONCLUSIVE" and not self.inconclusive_reason:
            raise ValueError("An inconclusive decision requires a reason")
