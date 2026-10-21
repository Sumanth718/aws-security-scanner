"""S3 checks (CIS AWS Foundations Benchmark v3.0, section 2.1)."""

from __future__ import annotations

import json

from ..context import ScanContext, error_code
from ..registry import Result, check

PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GRANTEES = ("http://acs.amazonaws.com/groups/global/AllUsers",
                   "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")


def _buckets(ctx: ScanContext) -> list[str]:
    return [b["Name"] for b in ctx.client("s3").list_buckets().get("Buckets", [])]


def _missing_flags(config: dict) -> list[str]:
    return [flag for flag in PAB_FLAGS if not config.get(flag)]


@check(id="S3-001", title="Account-level S3 Block Public Access is on", service="s3", severity="high",
       scope="global", cis="2.1.4",
       description="The account-wide setting stops any bucket from becoming public by mistake.",
       remediation="aws s3control put-public-access-block --account-id <id> --public-access-block-configuration "
                   "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
def account_public_access_block(ctx: ScanContext):
    try:
        config = ctx.client("s3control").get_public_access_block(
            AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
    except Exception as exc:
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            yield Result(False, f"account/{ctx.account_id}", "Not configured")
            return
        raise
    missing = _missing_flags(config)
    yield Result(not missing, f"account/{ctx.account_id}",
                 f"Disabled: {', '.join(missing)}" if missing else "All four settings enabled")


@check(id="S3-002", title="Bucket-level Block Public Access is on", service="s3", severity="high",
       scope="global", cis="2.1.4",
       description="Each bucket should block public ACLs and policies unless it is intentionally public.",
       remediation="aws s3api put-public-access-block --bucket <name> --public-access-block-configuration "
                   "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
def bucket_public_access_block(ctx: ScanContext):
    s3 = ctx.client("s3")
    for name in _buckets(ctx):
        try:
            config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except Exception as exc:
            if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                yield Result(False, f"s3://{name}", "Block Public Access is not configured")
                continue
            raise
        missing = _missing_flags(config)
        yield Result(not missing, f"s3://{name}",
                     f"Disabled: {', '.join(missing)}" if missing else "All four settings enabled")


@check(id="S3-003", title="Bucket ACL does not grant public access", service="s3", severity="critical",
       scope="global",
       description="ACL grants to AllUsers or AuthenticatedUsers expose objects to the internet.",
       remediation="Remove the public grant and set Object Ownership to BucketOwnerEnforced to disable ACLs.")
def bucket_acl_public(ctx: ScanContext):
    s3 = ctx.client("s3")
    for name in _buckets(ctx):
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        public = sorted({g["Permission"] for g in grants
                         if g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES})
        yield Result(not public, f"s3://{name}",
                     f"Public grants: {', '.join(public)}" if public else "No public grants")


def _denies_insecure_transport(policy: dict) -> bool:
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Deny":
            continue
        condition = stmt.get("Condition", {}).get("Bool", {})
        if str(condition.get("aws:SecureTransport", "")).lower() == "false":
            return True
    return False


@check(id="S3-004", title="Bucket policy enforces HTTPS", service="s3", severity="medium",
       scope="global", cis="2.1.1",
       description="Without a deny on aws:SecureTransport=false, data can be sent to the bucket in clear text.",
       remediation='Add a bucket policy statement with Effect "Deny", Principal "*", Action "s3:*" and '
                   'Condition {"Bool": {"aws:SecureTransport": "false"}}.')
def bucket_https_only(ctx: ScanContext):
    s3 = ctx.client("s3")
    for name in _buckets(ctx):
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
        except Exception as exc:
            if error_code(exc) == "NoSuchBucketPolicy":
                yield Result(False, f"s3://{name}", "No bucket policy, HTTP requests are allowed")
                continue
            raise
        ok = _denies_insecure_transport(policy)
        yield Result(ok, f"s3://{name}",
                     "Policy denies non-TLS requests" if ok else "Policy does not deny non-TLS requests")


@check(id="S3-005", title="Bucket versioning is enabled", service="s3", severity="low", scope="global",
       description="Versioning lets you recover objects after accidental deletion or ransomware.",
       remediation="aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled")
def bucket_versioning(ctx: ScanContext):
    s3 = ctx.client("s3")
    for name in _buckets(ctx):
        status = s3.get_bucket_versioning(Bucket=name).get("Status", "Never enabled")
        yield Result(status == "Enabled", f"s3://{name}", f"Versioning: {status}")
