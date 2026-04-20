from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    deletion_events = ["DeleteDBInstance", "DeleteDBCluster"]
    if event.get("eventName") not in deletion_events:
        return False
    return event.deep_get("errorCode") is None


def title(event):
    event_name = event.get("eventName", "Unknown")
    db_identifier = event.deep_get("requestParameters", "dBInstanceIdentifier") or event.deep_get(
        "requestParameters", "dBClusterIdentifier", default="<UNKNOWN>"
    )
    skip_snapshot = event.deep_get("requestParameters", "skipFinalSnapshot", default=False)
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    snapshot_warning = " [NO FINAL SNAPSHOT]" if skip_snapshot else ""
    if event_name == "DeleteDBInstance":
        return f"RDS Instance Deleted: [{db_identifier}] by [{user}]{snapshot_warning}"
    return f"RDS Cluster Deleted: [{db_identifier}] by [{user}]{snapshot_warning}"


def dedup(event):
    db_identifier = event.deep_get("requestParameters", "dBInstanceIdentifier") or event.deep_get(
        "requestParameters", "dBClusterIdentifier", default="unknown"
    )
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{db_identifier}"


def alert_context(event):
    context = aws_rds_context(event)
    context["skip_final_snapshot"] = event.deep_get(
        "requestParameters", "skipFinalSnapshot", default=False
    )
    context["final_snapshot_identifier"] = event.deep_get(
        "requestParameters", "finalDBSnapshotIdentifier"
    ) or event.deep_get("requestParameters", "finalDBClusterSnapshotIdentifier", default="N/A")
    context["delete_automated_backups"] = event.deep_get(
        "requestParameters", "deleteAutomatedBackups", default="N/A"
    )
    return context


def severity(event):
    skip_snapshot = event.deep_get("requestParameters", "skipFinalSnapshot", default=False)
    delete_backups = event.deep_get("requestParameters", "deleteAutomatedBackups", default=False)
    if skip_snapshot or delete_backups:
        return "CRITICAL"
    return "HIGH"
