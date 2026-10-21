"""A fake AWS account for demos and tests.

``FakeAWS`` returns client objects that mimic the boto3 calls the checks use,
backed by a plain dictionary. ``demo_state()`` describes a deliberately
misconfigured account so the scanner has something to find without real
credentials.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from typing import Any


class FakeClientError(Exception):
    """Mimics botocore.exceptions.ClientError closely enough for error_code()."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"An error occurred ({code}): {message or code}")
        self.response = {"Error": {"Code": code, "Message": message or code}}


class _Paginator:
    def __init__(self, method):
        self._method = method

    def paginate(self, **kwargs):
        yield self._method(**kwargs)


class _FakeClient:
    def __init__(self, state: dict, region: str, now: datetime) -> None:
        self.state = state
        self.region = region
        self.now = now

    def get_paginator(self, operation: str) -> _Paginator:
        return _Paginator(getattr(self, operation))


class FakeIAM(_FakeClient):
    def _user(self, name):
        for user in self.state["iam"]["users"]:
            if user["UserName"] == name:
                return user
        raise FakeClientError("NoSuchEntity", f"user {name} not found")

    def get_account_summary(self):
        return {"SummaryMap": dict(self.state["iam"]["summary"])}

    def get_account_password_policy(self):
        policy = self.state["iam"].get("password_policy")
        if policy is None:
            raise FakeClientError("NoSuchEntity", "The Password Policy cannot be found")
        return {"PasswordPolicy": dict(policy)}

    def list_users(self, **_):
        return {"Users": [{"UserName": u["UserName"]} for u in self.state["iam"]["users"]]}

    def get_login_profile(self, UserName):
        if not self._user(UserName).get("console"):
            raise FakeClientError("NoSuchEntity", "Login Profile cannot be found")
        return {"LoginProfile": {"UserName": UserName}}

    def list_mfa_devices(self, UserName, **_):
        user = self._user(UserName)
        devices = [{"SerialNumber": f"arn:aws:iam::mfa/{UserName}"}] if user.get("mfa") else []
        return {"MFADevices": devices}

    def list_access_keys(self, UserName, **_):
        keys = [{"AccessKeyId": k["id"], "Status": k.get("status", "Active"),
                 "CreateDate": self.now - timedelta(days=k["age_days"])}
                for k in self._user(UserName).get("keys", [])]
        return {"AccessKeyMetadata": keys}

    def list_attached_user_policies(self, UserName, **_):
        return {"AttachedPolicies": [{"PolicyName": p, "PolicyArn": f"arn:aws:iam::aws:policy/{p}"}
                                     for p in self._user(UserName).get("attached", [])]}

    def list_user_policies(self, UserName, **_):
        return {"PolicyNames": list(self._user(UserName).get("inline", []))}


class FakeS3(_FakeClient):
    def _bucket(self, name):
        try:
            return self.state["s3"]["buckets"][name]
        except KeyError:
            raise FakeClientError("NoSuchBucket", name) from None

    def list_buckets(self):
        return {"Buckets": [{"Name": n} for n in self.state["s3"]["buckets"]]}

    def get_public_access_block(self, Bucket):
        config = self._bucket(Bucket).get("public_access_block")
        if config is None:
            raise FakeClientError("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": dict(config)}

    def get_bucket_acl(self, Bucket):
        grants = [{"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}]
        for permission in self._bucket(Bucket).get("public_acl", []):
            grants.append({"Grantee": {"Type": "Group",
                                       "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                           "Permission": permission})
        return {"Grants": grants}

    def get_bucket_policy(self, Bucket):
        policy = self._bucket(Bucket).get("policy")
        if policy is None:
            raise FakeClientError("NoSuchBucketPolicy")
        return {"Policy": json.dumps(policy)}

    def get_bucket_versioning(self, Bucket):
        status = self._bucket(Bucket).get("versioning")
        return {"Status": status} if status else {}


class FakeS3Control(_FakeClient):
    def get_public_access_block(self, AccountId):
        config = self.state["s3"].get("account_public_access_block")
        if config is None:
            raise FakeClientError("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": dict(config)}


class FakeEC2(_FakeClient):
    @property
    def _region(self):
        return self.state["regions"][self.region]

    def describe_security_groups(self, Filters=None, **_):
        groups = self._region.get("security_groups", [])
        for f in Filters or []:
            if f["Name"] == "group-name":
                groups = [g for g in groups if g["GroupName"] in f["Values"]]
        return {"SecurityGroups": copy.deepcopy(groups)}

    def get_ebs_encryption_by_default(self):
        return {"EbsEncryptionByDefault": self._region.get("ebs_default_encryption", False)}

    def describe_instances(self, **_):
        return {"Reservations": [{"Instances": copy.deepcopy(self._region.get("instances", []))}]}

    def describe_vpcs(self, **_):
        return {"Vpcs": [{"VpcId": v} for v in self._region.get("vpcs", [])]}

    def describe_flow_logs(self, **_):
        return {"FlowLogs": [{"ResourceId": v, "FlowLogStatus": "ACTIVE"}
                             for v in self._region.get("flow_logs", [])]}


class FakeCloudTrail(_FakeClient):
    def describe_trails(self, includeShadowTrails=True):
        return {"trailList": [{k: v for k, v in t.items() if k != "IsLogging"}
                              for t in self.state["cloudtrail"]["trails"]]}

    def get_trail_status(self, Name):
        for trail in self.state["cloudtrail"]["trails"]:
            if Name in (trail["TrailARN"], trail["Name"]):
                if trail.get("HomeRegion") != self.region:
                    raise FakeClientError("TrailNotFoundException", "call from the home region")
                return {"IsLogging": trail.get("IsLogging", False)}
        raise FakeClientError("TrailNotFoundException", Name)


class FakeGuardDuty(_FakeClient):
    def list_detectors(self, **_):
        return {"DetectorIds": list(self.state["regions"][self.region].get("guardduty", {}))}

    def get_detector(self, DetectorId):
        return {"Status": self.state["regions"][self.region]["guardduty"][DetectorId]}


class FakeAccessAnalyzer(_FakeClient):
    def list_analyzers(self, **_):
        return {"analyzers": [{"name": n, "status": "ACTIVE"}
                              for n in self.state["regions"][self.region].get("analyzers", [])]}


_CLIENTS = {
    "iam": FakeIAM, "s3": FakeS3, "s3control": FakeS3Control, "ec2": FakeEC2,
    "cloudtrail": FakeCloudTrail, "guardduty": FakeGuardDuty, "accessanalyzer": FakeAccessAnalyzer,
}


class FakeAWS:
    """Client factory compatible with ScanContext(client_factory=...)."""

    def __init__(self, state: dict | None = None, now: datetime | None = None) -> None:
        self.state = state if state is not None else demo_state()
        self.now = now or datetime.now(timezone.utc)

    def __call__(self, service: str, region: str) -> Any:
        return _CLIENTS[service](self.state, region, self.now)

    @property
    def account_id(self) -> str:
        return self.state["account_id"]

    @property
    def regions(self) -> list[str]:
        return list(self.state["regions"])


# --------------------------------------------------------------------------- #
# Demo account
# --------------------------------------------------------------------------- #

_ALL_BLOCKED = {flag: True for flag in
                ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}


def _tls_policy(bucket: str) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}


def _sg(group_id, name, vpc, ingress=(), egress=()):
    return {"GroupId": group_id, "GroupName": name, "VpcId": vpc,
            "IpPermissions": list(ingress), "IpPermissionsEgress": list(egress)}


def _tcp(port_from, port_to, cidr="0.0.0.0/0"):
    key, field = ("Ipv6Ranges", "CidrIpv6") if ":" in cidr else ("IpRanges", "CidrIp")
    return {"IpProtocol": "tcp", "FromPort": port_from, "ToPort": port_to, key: [{field: cidr}]}


_ALL_OUT = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}


def demo_state() -> dict:
    """A fictional account with a realistic mix of good and bad configuration."""
    return {
        "account_id": "111122223333",
        "iam": {
            "summary": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1},
            "password_policy": {"MinimumPasswordLength": 8, "PasswordReusePrevention": 0},
            "users": [
                {"UserName": "alice", "console": True, "mfa": True,
                 "keys": [{"id": "AKIAEXAMPLEALICE0001", "age_days": 32}]},
                {"UserName": "bob", "console": True, "mfa": False, "attached": ["AdministratorAccess"],
                 "keys": [{"id": "AKIAEXAMPLEBOB000002", "age_days": 214}]},
                {"UserName": "ci-deployer", "console": False, "inline": ["deploy-to-s3"],
                 "keys": [{"id": "AKIAEXAMPLECI0000003", "age_days": 402},
                          {"id": "AKIAEXAMPLECI0000004", "age_days": 530, "status": "Inactive"}]},
                {"UserName": "carol", "console": True, "mfa": True},
            ],
        },
        "s3": {
            "account_public_access_block": None,
            "buckets": {
                "acme-cloudtrail-logs": {"public_access_block": _ALL_BLOCKED,
                                         "policy": _tls_policy("acme-cloudtrail-logs"),
                                         "versioning": "Enabled"},
                "acme-web-assets": {"public_access_block": dict(_ALL_BLOCKED, BlockPublicPolicy=False),
                                    "policy": _tls_policy("acme-web-assets"), "versioning": "Enabled"},
                "acme-finance-reports": {"public_access_block": None, "public_acl": ["READ"],
                                         "versioning": "Suspended"},
            },
        },
        "cloudtrail": {
            "trails": [{"Name": "org-trail", "HomeRegion": "eu-west-3", "IsMultiRegionTrail": True,
                        "TrailARN": "arn:aws:cloudtrail:eu-west-3:111122223333:trail/org-trail",
                        "LogFileValidationEnabled": False, "KmsKeyId": None, "IsLogging": True}],
        },
        "regions": {
            "eu-west-3": {
                "security_groups": [
                    _sg("sg-0a11default0000001", "default", "vpc-0paris00000000001"),
                    _sg("sg-0a11web00000000002", "web-alb", "vpc-0paris00000000001",
                        [_tcp(443, 443), _tcp(443, 443, "::/0")], [_ALL_OUT]),
                    _sg("sg-0a11bastion0000003", "bastion", "vpc-0paris00000000001",
                        [_tcp(22, 22)], [_ALL_OUT]),
                ],
                "ebs_default_encryption": True,
                "instances": [
                    {"InstanceId": "i-0paris0web00000001", "State": {"Name": "running"},
                     "MetadataOptions": {"HttpTokens": "required"}},
                    {"InstanceId": "i-0paris0bastion0002", "State": {"Name": "running"},
                     "MetadataOptions": {"HttpTokens": "optional"}},
                ],
                "vpcs": ["vpc-0paris00000000001"],
                "flow_logs": ["vpc-0paris00000000001"],
                "guardduty": {"d0paris": "ENABLED"},
                "analyzers": ["account-analyzer"],
            },
            "us-east-1": {
                "security_groups": [
                    _sg("sg-0b22default0000001", "default", "vpc-0virginia0000001",
                        [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-0b22default0000001"}]}],
                        [_ALL_OUT]),
                    _sg("sg-0b22legacy00000002", "legacy-windows", "vpc-0virginia0000001",
                        [_tcp(3380, 3390), _tcp(80, 80)], [_ALL_OUT]),
                ],
                "ebs_default_encryption": False,
                "instances": [
                    {"InstanceId": "i-0virginia0legacy01", "State": {"Name": "stopped"},
                     "MetadataOptions": {"HttpTokens": "optional"}},
                ],
                "vpcs": ["vpc-0virginia0000001"],
                "flow_logs": [],
                "guardduty": {},
                "analyzers": [],
            },
        },
    }
