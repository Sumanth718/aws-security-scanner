"""Unit tests for individual checks, using the fake AWS account."""

import unittest
from datetime import datetime, timezone

from awsscan.context import ScanContext
from awsscan.demo import FakeAWS, demo_state
from awsscan.scanner import run_scan, select_checks

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


def scan(state, check_id, regions=None):
    fake = FakeAWS(state, now=NOW)
    ctx = ScanContext(fake, regions or fake.regions, fake.account_id, home_region="eu-west-3", now=NOW)
    return run_scan(ctx, select_checks(ids=[check_id])).findings


def statuses(findings):
    return {(f.resource, f.region): f.status for f in findings}


class IamCheckTests(unittest.TestCase):
    def test_root_mfa_and_keys(self):
        state = demo_state()
        self.assertEqual(scan(state, "IAM-001")[0].status, "PASS")
        self.assertEqual(scan(state, "IAM-002")[0].status, "FAIL")
        state["iam"]["summary"] = {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}
        self.assertEqual(scan(state, "IAM-001")[0].status, "FAIL")
        self.assertEqual(scan(state, "IAM-002")[0].status, "PASS")

    def test_console_mfa_skips_programmatic_users(self):
        results = statuses(scan(demo_state(), "IAM-003"))
        self.assertEqual(results[("user/bob", "global")], "FAIL")
        self.assertEqual(results[("user/alice", "global")], "PASS")
        self.assertNotIn(("user/ci-deployer", "global"), results)

    def test_key_rotation_ignores_inactive_keys(self):
        findings = scan(demo_state(), "IAM-004")
        failed = {f.resource for f in findings if f.status == "FAIL"}
        self.assertEqual(failed, {"user/bob/AKIAEXAMPLEBOB000002", "user/ci-deployer/AKIAEXAMPLECI0000003"})
        self.assertFalse(any("AKIAEXAMPLECI0000004" in f.resource for f in findings))

    def test_password_policy(self):
        state = demo_state()
        self.assertIn("minimum length 8", scan(state, "IAM-005")[0].details)
        state["iam"]["password_policy"] = None
        self.assertEqual(scan(state, "IAM-005")[0].details, "No password policy is set")
        state["iam"]["password_policy"] = {"MinimumPasswordLength": 16, "PasswordReusePrevention": 24}
        self.assertEqual(scan(state, "IAM-005")[0].status, "PASS")

    def test_user_policies_flag_admin(self):
        findings = {f.resource: f for f in scan(demo_state(), "IAM-006")}
        self.assertIn("full administrator access", findings["user/bob"].details)
        self.assertEqual(findings["user/carol"].status, "PASS")


class S3CheckTests(unittest.TestCase):
    def test_account_public_access_block(self):
        state = demo_state()
        self.assertEqual(scan(state, "S3-001")[0].details, "Not configured")
        state["s3"]["account_public_access_block"] = {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
        self.assertEqual(scan(state, "S3-001")[0].status, "PASS")

    def test_bucket_public_access_block(self):
        results = {f.resource: f for f in scan(demo_state(), "S3-002")}
        self.assertEqual(results["s3://acme-cloudtrail-logs"].status, "PASS")
        self.assertEqual(results["s3://acme-web-assets"].details, "Disabled: BlockPublicPolicy")
        self.assertEqual(results["s3://acme-finance-reports"].status, "FAIL")

    def test_public_acl_and_https(self):
        acl = {f.resource: f.status for f in scan(demo_state(), "S3-003")}
        self.assertEqual(acl["s3://acme-finance-reports"], "FAIL")
        self.assertEqual(acl["s3://acme-web-assets"], "PASS")
        tls = {f.resource: f.status for f in scan(demo_state(), "S3-004")}
        self.assertEqual(tls, {"s3://acme-cloudtrail-logs": "PASS", "s3://acme-web-assets": "PASS",
                               "s3://acme-finance-reports": "FAIL"})


class NetworkCheckTests(unittest.TestCase):
    def test_admin_ports_including_port_ranges(self):
        results = {f.resource: f for f in scan(demo_state(), "EC2-001")}
        self.assertIn("22/SSH", results["sg-0a11bastion0000003 (bastion)"].details)
        # 3380-3390 includes 3389
        self.assertIn("3389/RDP", results["sg-0b22legacy00000002 (legacy-windows)"].details)
        self.assertEqual(results["sg-0a11web00000000002 (web-alb)"].status, "PASS")

    def test_all_traffic_rule_counts_as_exposed(self):
        state = demo_state()
        state["regions"]["eu-west-3"]["security_groups"][1]["IpPermissions"] = [
            {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
        results = {f.resource: f for f in scan(state, "EC2-001")}
        self.assertEqual(results["sg-0a11web00000000002 (web-alb)"].details, "Open to the internet: all ports")

    def test_default_sg_ebs_imds_flowlogs(self):
        self.assertEqual({f.region: f.status for f in scan(demo_state(), "EC2-002")},
                         {"eu-west-3": "PASS", "us-east-1": "FAIL"})
        self.assertEqual({f.region: f.status for f in scan(demo_state(), "EC2-003")},
                         {"eu-west-3": "PASS", "us-east-1": "FAIL"})
        imds = {f.resource: f.status for f in scan(demo_state(), "EC2-004")}
        self.assertEqual(imds["i-0paris0web00000001"], "PASS")
        self.assertEqual(imds["i-0paris0bastion0002"], "FAIL")
        self.assertEqual({f.resource: f.status for f in scan(demo_state(), "VPC-001")},
                         {"vpc-0paris00000000001": "PASS", "vpc-0virginia0000001": "FAIL"})


class MonitoringCheckTests(unittest.TestCase):
    def test_trail_logging_uses_home_region(self):
        state = demo_state()
        self.assertEqual(scan(state, "CT-001")[0].status, "PASS")
        state["cloudtrail"]["trails"][0]["IsLogging"] = False
        self.assertEqual(scan(state, "CT-001")[0].status, "FAIL")

    def test_no_trails(self):
        state = demo_state()
        state["cloudtrail"]["trails"] = []
        self.assertEqual(scan(state, "CT-001")[0].status, "FAIL")
        self.assertEqual(scan(state, "CT-002")[0].details, "No trails configured")

    def test_guardduty_suspended(self):
        state = demo_state()
        state["regions"]["us-east-1"]["guardduty"] = {"d1": "DISABLED"}
        results = {f.region: f for f in scan(state, "GD-001")}
        self.assertEqual(results["eu-west-3"].status, "PASS")
        self.assertEqual(results["us-east-1"].details, "Detector suspended")


if __name__ == "__main__":
    unittest.main()
