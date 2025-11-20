from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_base_helpers import deep_get

# Use this to record the names of your S3 buckets that have cloudtrail logs
#   If a bucket name isn't mentioned here, we still make a best guess as to whether or not it
#   contains CloudTrail data, but the confidence rating will be lower, and so will the severity
CLOUDTRAIL_BUCKETS = ("example_cloudtrail_bucket_name",)

# This is the minimum length fo time CloudTrail logs should remain in an S3 bucket.
#   We set this to 7 initially, since this is the recommended amount of time logs ingested by
#   Panther should remain available. You can modify this if you wish.
CLOUDTRAIL_MINIMUM_STORAGE_PERIOD_DAYS = 7


def rule(event):
    # Only alert for successful PutBucketLifecycle events
    if not (aws_cloudtrail_success(event) and event.get("eventName") == "PutBucketLifecycle"):
        return False

    # Exit out if the bucket doesn't have cloudtrail logs
    #   We check this be either comparing the bucket name to a list of buckets the user knows has
    #   CT logs, or by heuristically looking at the name and guessing whether it likely has CT logs
    bucket_name = event.deep_get("requestParameters", "bucketName")
    if not bucket_name or (
        not is_cloudtrail_bucket(bucket_name) and not guess_is_cloudtrail_bucket(bucket_name)
    ):
        return False

    # Don't alert if the Rule status is disabled
    lifecycle = event.deep_get("requestParameters", "LifecycleConfiguration", "Rule")
    if lifecycle.get("Status") != "Enabled":
        return False

    # Alert if the lifecycle period is short
    duration = deep_get(lifecycle, "Expiration", "Days", default=0)
    return duration < CLOUDTRAIL_MINIMUM_STORAGE_PERIOD_DAYS


def title(event):
    bucket_name = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN S3 BUCKET>")
    lifecycle = event.deep_get("requestParameters", "LifecycleConfiguration", "Rule")
    duration = deep_get(lifecycle, "Expiration", "Days", default=0)
    rule_id = lifecycle.get("ID", "<UNKNOWN RULE ID>")
    account = event.deep_get("userIdentity", "accountId", default="<UNKNOWN_AWS_ACCOUNT>")
    return (
        f"S3 Bucket {bucket_name} in account {account} "
        f"has new rule {rule_id} set to delete CloudTrail logs after "
        f"{duration} day{'s' if duration != 1 else ''}"
    )


def severity(event):
    # Return lower severity if we aren't positive this bucket has cloudtrail logs.
    bucket_name = event.deep_get("requestParameters", "bucketName")
    if not is_cloudtrail_bucket(bucket_name):
        return "LOW"
    return "DEFAULT"


def alert_context(event):
    context = aws_rule_context(event)

    # Add name of S3 bucket, Rule ID, and expiration duration to context
    bucket_name = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN S3 BUCKET>")
    lifecycle = event.deep_get("requestParameters", "LifecycleConfiguration", "Rule")
    duration = deep_get(lifecycle, "Expiration", "Days", default=0)
    rule_id = lifecycle.get("ID", "<UNKNOWN RULE ID>")
    context.update(
        {
            "bucketName": bucket_name,
            "lifecycleRuleID": rule_id,
            "lifecycleRuleDurationDays": duration,
        }
    )

    return context


def is_cloudtrail_bucket(bucket_name: str) -> bool:
    """Returns True if the bucket is known to contain CloudTrail logs."""
    return bucket_name in CLOUDTRAIL_BUCKETS


def guess_is_cloudtrail_bucket(bucket_name: str) -> bool:
    """Takes a best guess at whether a bucket contains CloudTrail logs or not."""
    # Maybe one day, this check will get more complex
    return "trail" in bucket_name.lower()
