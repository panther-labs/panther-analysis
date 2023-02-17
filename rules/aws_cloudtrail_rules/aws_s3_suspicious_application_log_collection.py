from panther_base_helpers import deep_get, aws_rule_context

# Deduplicaton and threshold events may vary on environment, adjust as needed.
# Detection filters can be applied to allowlist or blocklist to any ARNs needed.

# Add S3 buckets that contain applicaiton logs.
S3_buckets = {"EXAMPLE-BUCKET-NAME", "cloudtrail-dev"}

# Monitor S3 for events that are used to mine valuable information.
S3_EVENTS = ["GetObject", "ListObjects"]


def rule(event):
    # Pre-filtering as the first step in rule() is going to save tons of computation time.
    # Without somebody setting up [a CloudTrail collector for these events]
    # (https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html)
    # these particular S3_EVENTS would never appear in a cloudtrail.
    if event.get("eventName", "") not in S3_EVENTS:
        return False
    bucket_name = deep_get(event, "requestParameters", "bucketName", default="<NO_BUCKET>")
    return bucket_name in S3_buckets


def title(event):
    return (
        f"User [{deep_get(event, 'userIdentity', 'arn')}] "
        + f"executed [{event.get('eventName')}] "
        + f"against sensitive application log in [{event.get('recipientAccountId')}]."
    )


def alert_context(event):
    return aws_rule_context(event)
