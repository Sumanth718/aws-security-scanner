"""IAM checks (CIS AWS Foundations Benchmark v3.0, section 1)."""

from __future__ import annotations

from ..context import ScanContext, error_code
from ..registry import Result, check

MAX_KEY_AGE_DAYS = 90
MIN_PASSWORD_LENGTH = 14
MIN_PASSWORD_REUSE = 24


def _summary(ctx: ScanContext) -> dict:
    return ctx.client("iam").get_account_summary()["SummaryMap"]


@check(id="IAM-001", title="Root account has MFA enabled", service="iam", severity="critical",
       scope="global", cis="1.5",
       description="Without MFA, the root password alone gives full control of the account.",
       remediation="Sign in as root, open Security credentials and assign a hardware or virtual MFA device.")
def root_mfa(ctx: ScanContext):
    enabled = _summary(ctx).get("AccountMFAEnabled") == 1
    yield Result(enabled, "root", "MFA is enabled" if enabled else "Root account has no MFA device")


@check(id="IAM-002", title="Root account has no access keys", service="iam", severity="critical",
       scope="global", cis="1.4",
       description="Root access keys cannot be restricted by IAM policies and are a top target for attackers.",
       remediation="Delete root access keys under root Security credentials. Use IAM roles for automation.")
def root_access_keys(ctx: ScanContext):
    present = _summary(ctx).get("AccountAccessKeysPresent", 0) > 0
    yield Result(not present, "root", "Root access keys exist" if present else "No root access keys")


@check(id="IAM-003", title="IAM users with console access have MFA", service="iam", severity="high",
       scope="global", cis="1.10",
       description="Console passwords without MFA can be phished or guessed.",
       remediation="Enforce MFA for every console user, for example with a policy that denies all "
                   "actions when aws:MultiFactorAuthPresent is false.")
def console_users_mfa(ctx: ScanContext):
    iam = ctx.client("iam")
    for user in ctx.paginate(iam, "list_users", "Users"):
        name = user["UserName"]
        try:
            iam.get_login_profile(UserName=name)
        except Exception as exc:  # botocore ClientError
            if error_code(exc) == "NoSuchEntity":
                continue  # programmatic-only user, no console password
            raise
        devices = list(ctx.paginate(iam, "list_mfa_devices", "MFADevices", UserName=name))
        yield Result(bool(devices), f"user/{name}",
                     "MFA device assigned" if devices else "Console password without MFA")


@check(id="IAM-004", title="Active access keys are rotated within 90 days", service="iam", severity="medium",
       scope="global", cis="1.14",
       description="Long-lived keys are more likely to have leaked into code, logs or laptops.",
       remediation="Create a new key, update applications, then deactivate and delete the old key. "
                   "Prefer IAM roles or IAM Identity Center over long-lived keys.")
def access_key_rotation(ctx: ScanContext):
    iam = ctx.client("iam")
    for user in ctx.paginate(iam, "list_users", "Users"):
        name = user["UserName"]
        for key in ctx.paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=name):
            if key.get("Status") != "Active":
                continue
            age = (ctx.now - key["CreateDate"]).days
            yield Result(age <= MAX_KEY_AGE_DAYS, f"user/{name}/{key['AccessKeyId']}",
                         f"Key is {age} days old")


@check(id="IAM-005", title="Password policy meets CIS requirements", service="iam", severity="medium",
       scope="global", cis="1.8, 1.9",
       description=f"Passwords should be at least {MIN_PASSWORD_LENGTH} characters and not reuse "
                   f"the last {MIN_PASSWORD_REUSE} passwords.",
       remediation=f"aws iam update-account-password-policy --minimum-password-length {MIN_PASSWORD_LENGTH} "
                   f"--password-reuse-prevention {MIN_PASSWORD_REUSE}")
def password_policy(ctx: ScanContext):
    try:
        policy = ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
    except Exception as exc:
        if error_code(exc) == "NoSuchEntity":
            yield Result(False, "account-password-policy", "No password policy is set")
            return
        raise
    problems = []
    if policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH:
        problems.append(f"minimum length {policy.get('MinimumPasswordLength', 0)} < {MIN_PASSWORD_LENGTH}")
    if policy.get("PasswordReusePrevention", 0) < MIN_PASSWORD_REUSE:
        problems.append(f"reuse prevention {policy.get('PasswordReusePrevention', 0)} < {MIN_PASSWORD_REUSE}")
    yield Result(not problems, "account-password-policy", "; ".join(problems) or "Policy is compliant")


@check(id="IAM-006", title="IAM users receive permissions only through groups", service="iam",
       severity="medium", scope="global", cis="1.15",
       description="Policies attached to individual users are hard to audit and drift over time.",
       remediation="Move user policies to groups or roles and detach them from the user.")
def no_user_policies(ctx: ScanContext):
    iam = ctx.client("iam")
    for user in ctx.paginate(iam, "list_users", "Users"):
        name = user["UserName"]
        attached = [p["PolicyName"] for p in
                    ctx.paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name)]
        inline = list(ctx.paginate(iam, "list_user_policies", "PolicyNames", UserName=name))
        if not attached and not inline:
            yield Result(True, f"user/{name}", "No user-level policies")
            continue
        parts = []
        if attached:
            parts.append("attached: " + ", ".join(attached))
        if inline:
            parts.append("inline: " + ", ".join(inline))
        if "AdministratorAccess" in attached:
            parts.append("user has full administrator access")
        yield Result(False, f"user/{name}", "; ".join(parts))


@check(id="IAM-007", title="IAM Access Analyzer is enabled", service="accessanalyzer", severity="low",
       scope="regional", cis="1.20",
       description="Access Analyzer reports resources shared outside the account, such as public buckets or "
                   "cross-account roles.",
       remediation="aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT")
def access_analyzer(ctx: ScanContext, region: str):
    client = ctx.client("accessanalyzer", region)
    active = [a["name"] for a in ctx.paginate(client, "list_analyzers", "analyzers")
              if a.get("status") == "ACTIVE"]
    yield Result(bool(active), f"analyzer/{region}",
                 f"Active: {', '.join(active)}" if active else "No active analyzer in this region")
