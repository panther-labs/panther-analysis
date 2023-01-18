from panther_base_helpers import deep_get, aws_rule_context

# Deduplicaton and threshold events may vary on environment, adjust as needed.

# Add S3 buckets that contain applicaiton logs.
S3_buckets = {"EXAMPLE-BUCKET-NAME", "cloudtrail-dev"}

# Monitor S3 for events that are used to mine valuable information.
S3_EVENTS = ["GetObject", "ListObjects"]


def rule(event):
    bucket_name = deep_get(event, "requestParameters", "bucketName")
    return bucket_name in S3_buckets and event.get("eventName") in S3_EVENTS


def title(event):
    return (
        f"User ({deep_get(event, 'userIdentity', 'sessionContext', 'sessionIssuer', 'userName')})  "
        + f"performed a {event.get('eventName')} "
        + f"action in AWS account {event.get('recipientAccountId')}."
    )


def alert_context(event):
    return aws_rule_context(event)
