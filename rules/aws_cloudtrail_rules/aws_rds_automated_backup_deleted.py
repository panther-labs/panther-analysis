from panther_aws_helpers import aws_rule_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    deletion_events = ["DeleteDBInstanceAutomatedBackup", "DeleteDBClusterAutomatedBackup"]
    if event.get("eventName") not in deletion_events:
        return False
    return event.deep_get("errorCode") is None


def title(event):
    event_name = event.get("eventName", "Unknown")
    backup_arn = event.deep_get("requestParameters", "dbiResourceId") or event.deep_get(
        "requestParameters", "dbClusterResourceId", default="<UNKNOWN>"
    )
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    resource_type = (
        "Automated Backup" if event_name == "DeleteDBInstanceAutomatedBackup" else "Cluster Backup"
    )
    return f"RDS {resource_type} Deleted: [{backup_arn}] by [{user}]"


def dedup(event):
    backup_id = event.deep_get("requestParameters", "dbiResourceId") or event.deep_get(
        "requestParameters", "dbClusterResourceId", default="unknown"
    )
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{backup_id}"


def alert_context(event):
    context = aws_rule_context(event)
    context["dbi_resource_id"] = event.deep_get("requestParameters", "dbiResourceId", default="N/A")
    context["db_cluster_resource_id"] = event.deep_get(
        "requestParameters", "dbClusterResourceId", default="N/A"
    )
    context["backup_arn"] = event.deep_get(
        "responseElements", "dBInstanceAutomatedBackupArn"
    ) or event.deep_get("responseElements", "dBClusterAutomatedBackupArn", default="N/A")
    return context
