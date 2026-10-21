"""CloudTrail and GuardDuty checks (CIS AWS Foundations Benchmark v3.0, section 3)."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import Result, check


def _trails(ctx: ScanContext) -> list[dict]:
    return ctx.client("cloudtrail").describe_trails(includeShadowTrails=True).get("trailList", [])


@check(id="CT-001", title="A multi-region CloudTrail trail is logging", service="cloudtrail",
       severity="critical", scope="global", cis="3.1",
       description="CloudTrail is the audit log of every API call. Without it, incidents cannot be investigated.",
       remediation="aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> --is-multi-region-trail "
                   "--enable-log-file-validation && aws cloudtrail start-logging --name org-trail")
def multi_region_trail(ctx: ScanContext):
    active = []
    for trail in _trails(ctx):
        if not trail.get("IsMultiRegionTrail"):
            continue
        # get_trail_status must be called in the trail's home region
        client = ctx.client("cloudtrail", trail.get("HomeRegion") or ctx.home_region)
        if client.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
            active.append(trail["Name"])
    yield Result(bool(active), f"account/{ctx.account_id}",
                 f"Logging: {', '.join(active)}" if active else "No multi-region trail is logging")


@check(id="CT-002", title="CloudTrail log file validation is enabled", service="cloudtrail",
       severity="medium", scope="global", cis="3.2",
       description="Validation creates signed digests so you can prove logs were not modified or deleted.",
       remediation="aws cloudtrail update-trail --name <trail> --enable-log-file-validation")
def trail_validation(ctx: ScanContext):
    trails = _trails(ctx)
    if not trails:
        yield Result(False, f"account/{ctx.account_id}", "No trails configured")
    for trail in trails:
        ok = bool(trail.get("LogFileValidationEnabled"))
        yield Result(ok, f"trail/{trail['Name']}", "Enabled" if ok else "Disabled")


@check(id="CT-003", title="CloudTrail logs are encrypted with KMS", service="cloudtrail",
       severity="medium", scope="global", cis="3.5",
       description="A customer managed KMS key adds access control and an audit trail on log decryption.",
       remediation="aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>")
def trail_kms(ctx: ScanContext):
    for trail in _trails(ctx):
        ok = bool(trail.get("KmsKeyId"))
        yield Result(ok, f"trail/{trail['Name']}", "SSE-KMS enabled" if ok else "Using default S3 encryption")


@check(id="GD-001", title="GuardDuty is enabled", service="guardduty", severity="high",
       description="GuardDuty detects compromised credentials, crypto-mining and reconnaissance from "
                   "CloudTrail, VPC Flow Logs and DNS logs.",
       remediation="aws guardduty create-detector --enable --region <region>")
def guardduty_enabled(ctx: ScanContext, region: str):
    gd = ctx.client("guardduty", region)
    detectors = list(ctx.paginate(gd, "list_detectors", "DetectorIds"))
    enabled = [d for d in detectors if gd.get_detector(DetectorId=d).get("Status") == "ENABLED"]
    detail = "Enabled" if enabled else ("Detector suspended" if detectors else "No detector")
    yield Result(bool(enabled), f"guardduty/{region}", detail)
