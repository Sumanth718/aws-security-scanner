"""Runs registered checks and collects findings."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .context import ScanContext, error_code
from .models import SEVERITY_ORDER, CheckMeta, Finding
from .registry import CheckFunc, all_checks

SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 3, "low": 1, "info": 0}


@dataclass
class ScanResult:
    account_id: str
    regions: list[str]
    started_at: datetime
    findings: list[Finding] = field(default_factory=list)

    def by_status(self, status: str) -> list[Finding]:
        return [f for f in self.findings if f.status == status]

    @property
    def failed(self) -> list[Finding]:
        return sorted(self.by_status("FAIL"), key=lambda f: (-f.severity_rank, f.check_id, f.resource))

    @property
    def score(self) -> int:
        """Severity-weighted pass rate from 0 to 100."""
        weights = Counter()
        for f in self.findings:
            if f.status in ("PASS", "FAIL"):
                weights[f.status] += SEVERITY_WEIGHT[f.severity]
        total = weights["PASS"] + weights["FAIL"]
        return round(100 * weights["PASS"] / total) if total else 100

    def failed_by_severity(self) -> dict[str, int]:
        counts = Counter(f.severity for f in self.by_status("FAIL"))
        return {sev: counts[sev] for sev in SEVERITY_ORDER if counts[sev]}


def select_checks(services: list[str] | None = None, ids: list[str] | None = None,
                  min_severity: str | None = None) -> list[tuple[CheckMeta, CheckFunc]]:
    selected = all_checks()
    if services:
        wanted = {s.lower() for s in services}
        selected = [c for c in selected if c[0].service in wanted]
    if ids:
        wanted_ids = {i.upper() for i in ids}
        selected = [c for c in selected if c[0].id in wanted_ids]
    if min_severity:
        floor = SEVERITY_ORDER[min_severity]
        selected = [c for c in selected if SEVERITY_ORDER[c[0].severity] >= floor]
    return selected


def run_scan(ctx: ScanContext, checks: list[tuple[CheckMeta, CheckFunc]] | None = None) -> ScanResult:
    result = ScanResult(ctx.account_id, list(ctx.regions), ctx.now)
    for meta, func in checks if checks is not None else all_checks():
        regions = [None] if meta.scope == "global" else ctx.regions
        for region in regions:
            location = region or "global"
            try:
                outcomes = list(func(ctx) if region is None else func(ctx, region))
            except Exception as exc:  # one failing check must not stop the scan
                code = error_code(exc) or type(exc).__name__
                result.findings.append(Finding(
                    meta.id, meta.title, meta.service, meta.severity, "ERROR", "-", location,
                    f"{code}: {exc}", meta.cis, meta.remediation))
                continue
            for outcome in outcomes:
                result.findings.append(Finding(
                    meta.id, meta.title, meta.service, meta.severity,
                    "PASS" if outcome.passed else "FAIL", outcome.resource, location,
                    outcome.details, meta.cis, meta.remediation))
    return result
