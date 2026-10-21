"""Tests for the scanner engine, reports, CLI and IAM policy coverage."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from awsscan.cli import main
from awsscan.context import ScanContext
from awsscan.demo import FakeAWS, FakeClientError
from awsscan.registry import all_checks
from awsscan.report import write_csv, write_html, write_json
from awsscan.scanner import run_scan, select_checks

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


def demo_ctx(factory=None):
    fake = FakeAWS(now=NOW)
    return ScanContext(
        factory or fake,
        fake.regions,
        fake.account_id,
        home_region="eu-west-3",
        now=NOW,
    )


class ScannerTests(unittest.TestCase):
    def test_every_check_runs_without_errors_on_demo(self):
        result = run_scan(demo_ctx())
        self.assertEqual(result.by_status("ERROR"), [])
        self.assertEqual(
            {f.check_id for f in result.findings},
            {m.id for m, _ in all_checks()},
        )

    def test_regional_checks_run_once_per_region(self):
        result = run_scan(demo_ctx(), select_checks(ids=["EC2-003"]))
        self.assertEqual(
            sorted(f.region for f in result.findings),
            ["eu-west-3", "us-east-1"],
        )

    def test_access_denied_becomes_error_not_crash(self):
        fake = FakeAWS(now=NOW)

        class Denied:
            def __getattr__(self, name):
                def call(*args, **kwargs):
                    raise FakeClientError("AccessDenied", "not authorized")

                return call

        def factory(service, region):
            return Denied() if service == "guardduty" else fake(service, region)

        result = run_scan(
            demo_ctx(factory),
            select_checks(services=["guardduty", "ec2"]),
        )
        errors = result.by_status("ERROR")
        self.assertEqual({e.check_id for e in errors}, {"GD-001"})
        self.assertTrue(
            all(e.details.startswith("AccessDenied") for e in errors)
        )
        self.assertTrue(result.by_status("PASS"))

    def test_score_and_ordering(self):
        result = run_scan(demo_ctx())
        self.assertTrue(0 < result.score < 100)
        ranks = [f.severity_rank for f in result.failed]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_select_checks_filters(self):
        self.assertTrue(
            all(m.service == "s3" for m, _ in select_checks(services=["S3"]))
        )
        self.assertTrue(
            all(
                m.severity in ("critical", "high")
                for m, _ in select_checks(min_severity="high")
            )
        )
        self.assertEqual(
            [m.id for m, _ in select_checks(ids=["iam-001"])],
            ["IAM-001"],
        )


class ReportTests(unittest.TestCase):
    def test_reports_are_written(self):
        result = run_scan(demo_ctx())

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)

            write_json(result, out / "f.json")
            write_csv(result, out / "f.csv")
            write_html(result, out / "r.html")

            data = json.loads((out / "f.json").read_text())
            self.assertEqual(
                data["summary"]["FAIL"],
                len(result.by_status("FAIL")),
            )
            self.assertEqual(
                len((out / "f.csv").read_text().splitlines()),
                len(result.findings) + 1,
            )

            page = (out / "r.html").read_text()
            self.assertIn("acme-finance-reports", page)
            self.assertNotIn("<script", page)


class CliTests(unittest.TestCase):
    def test_demo_scan_and_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(["scan", "--demo", "--out", tmp]), 0)
            self.assertEqual(
                main(
                    [
                        "scan",
                        "--demo",
                        "--out",
                        tmp,
                        "--fail-on",
                        "critical",
                    ]
                ),
                2,
            )
            self.assertEqual(
                main(
                    [
                        "scan",
                        "--demo",
                        "--out",
                        tmp,
                        "--services",
                        "guardduty",
                        "--regions",
                        "eu-west-3",
                        "--fail-on",
                        "high",
                    ]
                ),
                0,
            )
            self.assertTrue((Path(tmp) / "report.html").exists())


class IamPolicyTests(unittest.TestCase):
    """The shipped read-only policy must allow every API call a full scan makes."""

    PREFIX: ClassVar[dict[str, str]] = {
        "iam": "iam",
        "s3": "s3",
        "s3control": "s3",
        "ec2": "ec2",
        "cloudtrail": "cloudtrail",
        "guardduty": "guardduty",
        "accessanalyzer": "access-analyzer",
    }

    # boto3 method -> IAM action, where the names do not line up
    SPECIAL: ClassVar[dict[tuple[str, str], str]] = {
        ("s3", "list_buckets"): "s3:ListAllMyBuckets",
        ("s3", "get_public_access_block"): "s3:GetBucketPublicAccessBlock",
        (
            "s3control",
            "get_public_access_block",
        ): "s3:GetAccountPublicAccessBlock",
    }

    def action(self, service, method):
        if (service, method) in self.SPECIAL:
            return self.SPECIAL[(service, method)]

        name = "".join(
            part.capitalize() for part in method.split("_")
        ).replace("Mfa", "MFA")

        return f"{self.PREFIX[service]}:{name}"

    def test_policy_covers_all_api_calls(self):
        fake = FakeAWS(now=NOW)
        calls = set()

        class Recorder:
            def __init__(self, service, client):
                self._service = service
                self._client = client

            def get_paginator(self, operation):
                calls.add((self._service, operation))
                return self._client.get_paginator(operation)

            def __getattr__(self, name):
                calls.add((self._service, name))
                return getattr(self._client, name)

        run_scan(
            demo_ctx(
                lambda svc, region: Recorder(svc, fake(svc, region))
            )
        )

        policy = json.loads(
            (ROOT / "iam-policy" / "awsscan-readonly.json").read_text()
        )
        allowed = set(policy["Statement"][0]["Action"])
        needed = {
            self.action(service, method)
            for service, method in calls
        }

        self.assertGreater(len(needed), 15)
        self.assertEqual(sorted(needed - allowed), [])


if __name__ == "__main__":
    unittest.main()