"""Command-line interface.

Examples::

    python -m awsscan scan --demo
    python -m awsscan scan --profile audit --regions eu-west-3,us-east-1
    python -m awsscan scan --services s3,iam --fail-on high
    python -m awsscan list-checks
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .context import ScanContext
from .demo import FakeAWS
from .models import SEVERITY_ORDER
from .registry import all_checks
from .report import console_report, write_csv, write_html, write_json
from .scanner import run_scan, select_checks


def _aws_context(profile: str | None, regions: list[str] | None) -> ScanContext:
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise SystemExit("boto3 is required for real scans: pip install boto3 (or run with --demo)")

    session = boto3.Session(profile_name=profile)
    config = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    home = session.region_name or "us-east-1"
    account_id = session.client("sts", region_name=home, config=config).get_caller_identity()["Account"]
    if not regions:
        ec2 = session.client("ec2", region_name=home, config=config)
        regions = sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])

    def factory(service: str, region: str):
        return session.client(service, region_name=region, config=config)

    return ScanContext(factory, regions, account_id, home_region=home)


def _cmd_scan(args: argparse.Namespace) -> int:
    regions = [r.strip() for r in args.regions.split(",")] if args.regions else None
    if args.demo:
        fake = FakeAWS()
        ctx = ScanContext(fake, regions or fake.regions, fake.account_id, home_region="eu-west-3")
        print("Running against the built-in demo account (no AWS calls are made).\n")
    else:
        ctx = _aws_context(args.profile, regions)

    checks = select_checks(
        services=args.services.split(",") if args.services else None,
        ids=args.checks.split(",") if args.checks else None,
        min_severity=args.min_severity,
    )
    result = run_scan(ctx, checks)
    print(console_report(result))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(result, out / "findings.json")
    write_csv(result, out / "findings.csv")
    write_html(result, out / "report.html")
    print(f"\nReports written to {out}/ (report.html, findings.json, findings.csv)")

    if args.fail_on:
        floor = SEVERITY_ORDER[args.fail_on]
        if any(f.severity_rank >= floor for f in result.failed):
            return 2
    return 0


def _cmd_list(_: argparse.Namespace) -> int:
    for meta, _func in all_checks():
        print(f"{meta.id:<8} {meta.severity:<9} {meta.scope:<9} CIS {meta.cis:<9} {meta.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="awsscan",
                                     description="Audit an AWS account against CIS-aligned security checks.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan an AWS account")
    scan.add_argument("--demo", action="store_true", help="scan a built-in fake account (no credentials needed)")
    scan.add_argument("--profile", help="AWS CLI profile to use")
    scan.add_argument("--regions", help="comma-separated regions (default: all enabled regions)")
    scan.add_argument("--services", help="limit to services, e.g. iam,s3,ec2,cloudtrail,guardduty")
    scan.add_argument("--checks", help="limit to check IDs, e.g. IAM-001,S3-003")
    scan.add_argument("--min-severity", choices=list(SEVERITY_ORDER), help="skip checks below this severity")
    scan.add_argument("--out", default="reports", help="output directory (default: reports)")
    scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                      help="exit with code 2 if a check at or above this severity fails")
    scan.set_defaults(func=_cmd_scan)

    lst = sub.add_parser("list-checks", help="list available checks")
    lst.set_defaults(func=_cmd_list)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
