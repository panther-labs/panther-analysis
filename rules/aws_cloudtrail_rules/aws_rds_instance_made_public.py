from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    modify_events = ["ModifyDBInstance", "ModifyDBCluster"]
    if event.get("eventName") not in modify_events:
        return False
    if event.deep_get("errorCode") is not None:
        return False
    publicly_accessible = event.deep_get("requestParameters", "publiclyAccessible", default=None)
    if publicly_accessible is True:
        return True
    return False


def title(event):
    event_name = event.get("eventName", "Unknown")
    db_identifier = event.deep_get("requestParameters", "dBInstanceIdentifier") or event.deep_get(
        "requestParameters", "dBClusterIdentifier", default="<UNKNOWN>"
    )
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    resource_type = "Instance" if event_name == "ModifyDBInstance" else "Cluster"
    return f"RDS {resource_type} Made Public: [{db_identifier}] by [{user}]"


def alert_context(event):
    context = aws_rds_context(event)
    context["publicly_accessible"] = event.deep_get(
        "requestParameters", "publiclyAccessible", default="N/A"
    )
    context["apply_immediately"] = event.deep_get(
        "requestParameters", "applyImmediately", default="N/A"
    )
    vpc_security_groups = event.deep_get("requestParameters", "vPCSecurityGroupIds", default=None)
    if vpc_security_groups:
        context["vpc_security_groups_modified"] = vpc_security_groups
    subnet_group = event.deep_get("requestParameters", "dBSubnetGroupName")
    if subnet_group:
        context["subnet_group_modified"] = subnet_group
    return context
