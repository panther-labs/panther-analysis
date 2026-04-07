from panther_aws_helpers import aws_rds_context


def rule(event):
    return all(
        [
            event.get("eventSource") == "rds.amazonaws.com",
            event.get("eventName") == "StartExportTask",
            event.deep_get("errorCode") is None,
        ]
    )


def title(event):
    db_identifier = (
        event.deep_get("requestParameters", "sourceArn", default="<UNKNOWN_SOURCE>")
        .split(":")[-1]
        .split("/")[-1]
    )
    s3_bucket = event.deep_get("requestParameters", "s3BucketName", default="<UNKNOWN_BUCKET>")
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    return f"RDS Snapshot Export: [{db_identifier}] exported to S3 bucket [{s3_bucket}] by [{user}]"


def dedup(event):
    db_identifier = (
        event.deep_get("requestParameters", "sourceArn", default="<UNKNOWN_SOURCE>")
        .split(":")[-1]
        .split("/")[-1]
    )
    account_id = event.deep_get("recipientAccountId", default="unknown")
    region = event.get("awsRegion", "unknown")
    return f"{account_id}:{region}:{db_identifier}"


def alert_context(event):
    context = aws_rds_context(event)
    context["export_task_id"] = event.deep_get(
        "responseElements", "exportTaskIdentifier", default="N/A"
    )
    context["source_arn"] = event.deep_get("requestParameters", "sourceArn", default="N/A")
    context["s3_bucket"] = event.deep_get("requestParameters", "s3BucketName", default="N/A")
    context["s3_prefix"] = event.deep_get("requestParameters", "s3Prefix", default="N/A")
    context["kms_key_id"] = event.deep_get("requestParameters", "kmsKeyId", default="N/A")
    context["iam_role_arn"] = event.deep_get("requestParameters", "iamRoleArn", default="N/A")
    return context
