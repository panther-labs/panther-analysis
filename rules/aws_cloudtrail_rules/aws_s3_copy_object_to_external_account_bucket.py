from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def extract_resources(event):
    resources = event.get("resources", [])
    bucket_accounts = {}

    if len(resources) > 0:
        for resource in resources:
            if resource.get("type") == "AWS::S3::Bucket":
                bucket_name = resource.get("arn", "").split(":::")[-1]
                account_id = resource.get("accountId", "")
                bucket_accounts[bucket_name] = account_id
    return bucket_accounts


def rule(event):
    if event.get("eventName") != "CopyObject" or not aws_cloudtrail_success(event):
        return False

    bucket_accounts = extract_resources(event)

    # Need at least 2 buckets to compare accounts
    if len(bucket_accounts) < 2:
        return False

    # Check if buckets belong to different accounts
    account_ids = set(bucket_accounts.values())
    if len(account_ids) > 1:
        return True

    return False


def title(event):
    dest_bucket = event.deep_get(
        "requestParameters", "bucketName", default="<UNKNOWN_DESTINATION_BUCKET>"
    )
    source_bucket = event.deep_get(
        "requestParameters", "x-amz-copy-source", default="<UNKNOWN_SOURCE_BUCKET>"
    )
    actor = event.udm("actor_user")

    return (
        f"[AWS.CloudTrail] User [{actor}] copied objects to external AWS account "
        f"bucket [{dest_bucket}] from bucket [{source_bucket}]"
    )


def alert_context(event):
    context = aws_rule_context(event)
    context["bucket_accounts"] = extract_resources(event)
    context["dest_bucket"] = event.deep_get(
        "requestParameters", "bucketName", default="<UNKNOWN_DESTINATION_BUCKET>"
    )
    # Extract just the bucket name from x-amz-copy-source (format: bucket/key)
    source_path = event.deep_get(
        "requestParameters", "x-amz-copy-source", default="<UNKNOWN_SOURCE_BUCKET>"
    )
    context["bucketName"] = source_path.split("/")[0] if "/" in source_path else source_path
    return context
