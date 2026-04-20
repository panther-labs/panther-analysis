from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    modify_events = ["ModifyDBInstance", "ModifyDBCluster"]
    if event.get("eventName") not in modify_events:
        return False
    if event.deep_get("errorCode") is not None:
        return False
    deletion_protection = event.deep_get("requestParameters", "deletionProtection", default=None)
    if deletion_protection is False:
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
    return f"RDS {resource_type} Deletion Protection Disabled: [{db_identifier}] by [{user}]"


def dedup(event):
    db_identifier = event.deep_get("requestParameters", "dBInstanceIdentifier") or event.deep_get(
        "requestParameters", "dBClusterIdentifier", default="unknown"
    )
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{db_identifier}"


def alert_context(event):
    context = aws_rds_context(event)
    context["deletion_protection"] = event.deep_get(
        "requestParameters", "deletionProtection", default="N/A"
    )
    context["apply_immediately"] = event.deep_get(
        "requestParameters", "applyImmediately", default="N/A"
    )
    backup_retention = event.deep_get("requestParameters", "backupRetentionPeriod", default=None)
    if backup_retention is not None:
        context["backup_retention_period"] = backup_retention
    publicly_accessible = event.deep_get("requestParameters", "publiclyAccessible", default=None)
    if publicly_accessible is not None:
        context["publicly_accessible_changed"] = publicly_accessible
    return context
