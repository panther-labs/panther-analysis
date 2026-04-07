from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    deletion_events = ["DeleteDBSnapshot", "DeleteDBClusterSnapshot"]
    if event.get("eventName") not in deletion_events:
        return False
    return event.deep_get("errorCode") is None


def title(event):
    event_name = event.get("eventName", "Unknown")
    snapshot_id = event.deep_get("requestParameters", "dBSnapshotIdentifier") or event.deep_get(
        "requestParameters", "dBClusterSnapshotIdentifier", default="<UNKNOWN>"
    )
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    resource_type = "Snapshot" if event_name == "DeleteDBSnapshot" else "Cluster Snapshot"
    return f"RDS {resource_type} Deleted: [{snapshot_id}] by [{user}]"


def dedup(event):
    snapshot_id = event.deep_get("requestParameters", "dBSnapshotIdentifier") or event.deep_get(
        "requestParameters", "dBClusterSnapshotIdentifier", default="unknown"
    )
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{snapshot_id}"


def alert_context(event):
    context = aws_rds_context(event)
    context["snapshot_identifier"] = event.deep_get(
        "requestParameters", "dBSnapshotIdentifier"
    ) or event.deep_get("requestParameters", "dBClusterSnapshotIdentifier", default="N/A")
    context["snapshot_arn"] = event.deep_get("responseElements", "dBSnapshotArn") or event.deep_get(
        "responseElements", "dBClusterSnapshotArn", default="N/A"
    )
    return context
