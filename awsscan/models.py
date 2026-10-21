"""Data models for checks and findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    service: str
    severity: str
    scope: str  # "global" runs once, "regional" runs in every scanned region
    cis: str = "-"
    description: str = ""
    remediation: str = ""


@dataclass
class Finding:
    check_id: str
    title: str
    service: str
    severity: str
    status: str  # PASS | FAIL | ERROR
    resource: str
    region: str
    details: str = ""
    cis: str = "-"
    remediation: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
