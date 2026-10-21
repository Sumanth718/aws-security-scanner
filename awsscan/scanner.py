"""Runs registered checks and collects findings."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .context import ScanContext, error_code
from .models import SEVERITY_ORDER, CheckMeta, Finding
from .registry import CheckFunc, all_checks

SEVERITY_WEIGHT = {
    "critical": 10,
    "high": 5,
    "medium": 3,
    "low": 1,
    "info": 0,
}


@dataclass
class ScanResult:
    account_id: str
    regions: list[str]
    started_at: datetime
    findings: list[Finding] = field(default_factory=list)

    def by_status(self, status: str) -> list[Finding]:
        """Return findings matching the specified status."""
        return [finding for finding in self.findings if finding.status == status]

    @property
    def failed(self) -> list[Finding]:
        """Return failed findings ordered by severity and resource."""
        return sorted(
            self.by_status("FAIL"),
            key=lambda finding: (
                -finding.severity_rank,
                finding.check_id,
                finding.resource,
            ),
        )

    @property
    def score(self) -> int:
        """Calculate the severity-weighted pass rate from 0 to 100."""
        weights = Counter()

        for finding in self.findings:
            if finding.status in ("PASS", "FAIL"):
                weights[finding.status] += SEVERITY_WEIGHT[finding.severity]

        total = weights["PASS"] + weights["FAIL"]

        return round(100 * weights["PASS"] / total) if total else 100

    def failed_by_severity(self) -> dict[str, int]:
        """Count failed findings by severity."""
        counts = Counter(
            finding.severity for finding in self.by_status("FAIL")
        )

        return {
            severity: counts[severity]
            for severity in SEVERITY_ORDER
            if counts[severity]
        }


def select_checks(
    services: list[str] | None = None,
    ids: list[str] | None = None,
    min_severity: str | None = None,
) -> list[tuple[CheckMeta, CheckFunc]]:
    """Select security checks by service, ID, and minimum severity."""
    selected = all_checks()

    if services:
        wanted_services = {service.lower() for service in services}
        selected = [
            check
            for check in selected
            if check[0].service in wanted_services
        ]

    if ids:
        wanted_ids = {check_id.upper() for check_id in ids}
        selected = [
            check for check in selected if check[0].id in wanted_ids
        ]

    if min_severity:
        floor = SEVERITY_ORDER[min_severity]
        selected = [
            check
            for check in selected
            if SEVERITY_ORDER[check[0].severity] >= floor
        ]

    return selected


def run_scan(
    ctx: ScanContext,
    checks: list[tuple[CheckMeta, CheckFunc]] | None = None,
) -> ScanResult:
    """Run selected security checks and collect their findings."""
    result = ScanResult(ctx.account_id, list(ctx.regions), ctx.now)

    selected_checks = checks if checks is not None else all_checks()

    for meta, func in selected_checks:
        regions = [None] if meta.scope == "global" else ctx.regions

        for region in regions:
            location = region or "global"

            try:
                outcomes = list(
                    func(ctx) if region is None else func(ctx, region)
                )
            except Exception as exc:  # noqa: BLE001
                # Isolate check failures so one failing service does not
                # prevent the remaining security checks from running.
                code = error_code(exc) or type(exc).__name__

                result.findings.append(
                    Finding(
                        meta.id,
                        meta.title,
                        meta.service,
                        meta.severity,
                        "ERROR",
                        "-",
                        location,
                        f"{code}: {exc}",
                        meta.cis,
                        meta.remediation,
                    )
                )
                continue

            for outcome in outcomes:
                result.findings.append(
                    Finding(
                        meta.id,
                        meta.title,
                        meta.service,
                        meta.severity,
                        "PASS" if outcome.passed else "FAIL",
                        outcome.resource,
                        location,
                        outcome.details,
                        meta.cis,
                        meta.remediation,
                    )
                )

    return result