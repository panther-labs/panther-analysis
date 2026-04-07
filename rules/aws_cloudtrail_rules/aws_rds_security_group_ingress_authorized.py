from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    if event.get("eventName") != "AuthorizeDBSecurityGroupIngress":
        return False
    return event.deep_get("errorCode") is None


def title(event):
    security_group = event.deep_get("requestParameters", "dBSecurityGroupName", default="<UNKNOWN>")
    cidr_ip = event.deep_get("requestParameters", "cIDRIP", default="")
    ec2_group = event.deep_get("requestParameters", "eC2SecurityGroupName", default="")
    source = cidr_ip if cidr_ip else ec2_group if ec2_group else "<UNKNOWN_SOURCE>"
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    return f"RDS Security Group Ingress Authorized: [{security_group}] from [{source}] by [{user}]"


def dedup(event):
    security_group = event.deep_get("requestParameters", "dBSecurityGroupName", default="unknown")
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{security_group}"


def alert_context(event):
    context = aws_rds_context(event)
    context["security_group_name"] = event.deep_get(
        "requestParameters", "dBSecurityGroupName", default="N/A"
    )
    context["cidr_ip"] = event.deep_get("requestParameters", "cIDRIP", default="N/A")
    context["ec2_security_group_name"] = event.deep_get(
        "requestParameters", "eC2SecurityGroupName", default="N/A"
    )
    context["ec2_security_group_id"] = event.deep_get(
        "requestParameters", "eC2SecurityGroupId", default="N/A"
    )
    context["ec2_security_group_owner_id"] = event.deep_get(
        "requestParameters", "eC2SecurityGroupOwnerId", default="N/A"
    )
    return context


def severity(event):
    cidr_ip = event.deep_get("requestParameters", "cIDRIP", default="")
    if cidr_ip == "0.0.0.0/0":
        return "CRITICAL"
    return "MEDIUM"
