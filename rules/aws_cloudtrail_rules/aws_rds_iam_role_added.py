from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    role_events = ["AddRoleToDBInstance", "AddRoleToDBCluster"]
    if event.get("eventName") not in role_events:
        return False
    return event.deep_get("errorCode") is None


def title(event):
    event_name = event.get("eventName", "Unknown")
    db_identifier = event.deep_get("requestParameters", "dBInstanceIdentifier") or event.deep_get(
        "requestParameters", "dBClusterIdentifier", default="<UNKNOWN>"
    )
    role_arn = event.deep_get("requestParameters", "roleArn", default="<UNKNOWN_ROLE>")
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    resource_type = "Instance" if event_name == "AddRoleToDBInstance" else "Cluster"
    return f"IAM Role Added to RDS {resource_type}: [{db_identifier}] role [{role_arn}] by [{user}]"


def dedup(event):
    db_identifier = event.deep_get("requestParameters", "dBInstanceIdentifier") or event.deep_get(
        "requestParameters", "dBClusterIdentifier", default="unknown"
    )
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{db_identifier}"


def alert_context(event):
    context = aws_rds_context(event)
    context["role_arn"] = event.deep_get("requestParameters", "roleArn", default="N/A")
    context["feature_name"] = event.deep_get("requestParameters", "featureName", default="N/A")
    return context
