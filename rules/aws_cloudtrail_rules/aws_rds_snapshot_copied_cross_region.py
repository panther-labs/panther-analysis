from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    copy_events = ["CopyDBSnapshot", "CopyDBClusterSnapshot"]
    if event.get("eventName") not in copy_events:
        return False
    if event.deep_get("errorCode") is not None:
        return False
    source_region = event.deep_get("requestParameters", "sourceRegion", default="")
    target_region = event.get("awsRegion", "")
    if source_region and target_region and source_region != target_region:
        return True
    return False


def title(event):
    event_name = event.get("eventName", "Unknown")
    source_id = event.deep_get("requestParameters", "sourceDBSnapshotIdentifier") or event.deep_get(
        "requestParameters", "sourceDBClusterSnapshotIdentifier", default="<UNKNOWN>"
    )
    source_region = event.deep_get("requestParameters", "sourceRegion", default="<UNKNOWN>")
    target_region = event.get("awsRegion", "<UNKNOWN>")
    resource_type = "Snapshot" if event_name == "CopyDBSnapshot" else "Cluster Snapshot"
    return (
        f"RDS {resource_type} Copied Cross-Region: [{source_id}] "
        f"from [{source_region}] to [{target_region}]"
    )


def dedup(event):
    target_id = event.deep_get("requestParameters", "targetDBSnapshotIdentifier") or event.deep_get(
        "requestParameters", "targetDBClusterSnapshotIdentifier", default="unknown"
    )
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{target_id}"


def alert_context(event):
    context = aws_rds_context(event)
    context["source_snapshot_identifier"] = event.deep_get(
        "requestParameters", "sourceDBSnapshotIdentifier"
    ) or event.deep_get("requestParameters", "sourceDBClusterSnapshotIdentifier", default="N/A")
    context["target_snapshot_identifier"] = event.deep_get(
        "requestParameters", "targetDBSnapshotIdentifier"
    ) or event.deep_get("requestParameters", "targetDBClusterSnapshotIdentifier", default="N/A")
    context["source_region"] = event.deep_get("requestParameters", "sourceRegion", default="N/A")
    context["kms_key_id"] = event.deep_get("requestParameters", "kmsKeyId", default="N/A")
    context["copy_tags"] = event.deep_get("requestParameters", "copyTags", default="N/A")
    return context
