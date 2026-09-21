from urllib.parse import unquote

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def copy_source_bucket(event):
    # CloudTrail records x-amz-copy-source as "/bucket/key" (leading slash) and URL-encodes
    # the value, so a naive split on "/" yields an empty bucket name for most real events.
    # Normalize both so the source bucket matches the DeleteObject bucketName in correlation.
    source_path = unquote(
        event.deep_get("requestParameters", "x-amz-copy-source", default="")
    ).lstrip("/")
    return source_path.split("/")[0] if source_path else "<UNKNOWN_SOURCE_BUCKET>"


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
    source_bucket = copy_source_bucket(event)
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
    # bucketName is the copy *source* bucket, matched against the DeleteObject bucketName
    # in the AWS.S3.ObjectExfiltration.WITH.ObjectDeletion correlation rule.
    context["bucketName"] = copy_source_bucket(event)
    return context
