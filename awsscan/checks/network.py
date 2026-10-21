"""EC2 and VPC checks (CIS AWS Foundations Benchmark v3.0, sections 2.2, 3.7 and 5)."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import Result, check

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _open_ranges(permission: dict) -> list[str]:
    cidrs = [r.get("CidrIp") for r in permission.get("IpRanges", [])]
    cidrs += [r.get("CidrIpv6") for r in permission.get("Ipv6Ranges", [])]
    return [c for c in cidrs if c in OPEN_CIDRS]


def _exposed_admin_ports(permission: dict) -> list[str]:
    if not _open_ranges(permission):
        return []
    if permission.get("IpProtocol") == "-1":
        return ["all ports"]
    low, high = permission.get("FromPort"), permission.get("ToPort")
    if low is None or high is None:
        return []
    return [f"{port}/{name}" for port, name in ADMIN_PORTS.items() if low <= port <= high]


@check(id="EC2-001", title="No security group allows admin ports from the internet", service="ec2",
       severity="high", cis="5.2, 5.3",
       description="SSH or RDP open to 0.0.0.0/0 or ::/0 invites brute force and exploitation.",
       remediation="Restrict the rule to known IP ranges, or remove it and use Systems Manager Session Manager.")
def admin_ports_open(ctx: ScanContext, region: str):
    ec2 = ctx.client("ec2", region)
    for group in ctx.paginate(ec2, "describe_security_groups", "SecurityGroups"):
        exposed = sorted({p for perm in group.get("IpPermissions", []) for p in _exposed_admin_ports(perm)})
        resource = f"{group['GroupId']} ({group.get('GroupName', '')})"
        yield Result(not exposed, resource,
                     f"Open to the internet: {', '.join(exposed)}" if exposed else "No admin ports open")


@check(id="EC2-002", title="Default security groups restrict all traffic", service="ec2",
       severity="medium", cis="5.4",
       description="Resources launched without a chosen group land in the default group, so it should have "
                   "no rules.",
       remediation="Remove every inbound and outbound rule from each VPC's default security group.")
def default_sg_closed(ctx: ScanContext, region: str):
    ec2 = ctx.client("ec2", region)
    groups = ctx.paginate(ec2, "describe_security_groups", "SecurityGroups",
                          Filters=[{"Name": "group-name", "Values": ["default"]}])
    for group in groups:
        rules = len(group.get("IpPermissions", [])) + len(group.get("IpPermissionsEgress", []))
        yield Result(rules == 0, f"{group['GroupId']} ({group.get('VpcId', '')})",
                     f"{rules} rule(s) present" if rules else "No rules")


@check(id="EC2-003", title="EBS encryption by default is enabled", service="ec2", severity="medium",
       cis="2.2.1",
       description="New EBS volumes and snapshots should be encrypted automatically.",
       remediation="aws ec2 enable-ebs-encryption-by-default --region <region>")
def ebs_default_encryption(ctx: ScanContext, region: str):
    enabled = ctx.client("ec2", region).get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
    yield Result(enabled, f"ebs-default/{region}", "Enabled" if enabled else "Disabled")


@check(id="EC2-004", title="Instances require IMDSv2", service="ec2", severity="medium", cis="5.6",
       description="IMDSv1 can be abused through SSRF to steal instance role credentials.",
       remediation="aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required")
def imdsv2_required(ctx: ScanContext, region: str):
    ec2 = ctx.client("ec2", region)
    for reservation in ctx.paginate(ec2, "describe_instances", "Reservations"):
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") == "terminated":
                continue
            tokens = instance.get("MetadataOptions", {}).get("HttpTokens", "optional")
            yield Result(tokens == "required", instance["InstanceId"], f"HttpTokens={tokens}")


@check(id="VPC-001", title="VPC flow logs are enabled", service="ec2", severity="medium", cis="3.7",
       description="Flow logs record network traffic metadata needed for incident investigation.",
       remediation="aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL "
                   "--log-destination-type cloud-watch-logs --log-group-name <group> "
                   "--deliver-logs-permission-arn <role-arn>")
def vpc_flow_logs(ctx: ScanContext, region: str):
    ec2 = ctx.client("ec2", region)
    logged = {f["ResourceId"] for f in ctx.paginate(ec2, "describe_flow_logs", "FlowLogs")
              if f.get("FlowLogStatus", "ACTIVE") == "ACTIVE"}
    for vpc in ctx.paginate(ec2, "describe_vpcs", "Vpcs"):
        vpc_id = vpc["VpcId"]
        yield Result(vpc_id in logged, vpc_id, "Flow logs active" if vpc_id in logged else "No flow logs")
