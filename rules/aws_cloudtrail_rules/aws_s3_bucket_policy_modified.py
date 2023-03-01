from panther_base_helpers import aws_rule_context, deep_get
from panther_default import aws_cloudtrail_success

# API calls that are indicative of KMS CMK Deletion
S3_POLICY_CHANGE_EVENTS = {
    "PutBucketAcl",
    "PutBucketPolicy",
    "PutBucketCors",
    "PutBucketLifecycle",
    "PutBucketReplication",
    "DeleteBucketPolicy",
    "DeleteBucketCors",
    "DeleteBucketLifecycle",
    "DeleteBucketReplication",
}


def rule(event):
    return event.get("eventName") in S3_POLICY_CHANGE_EVENTS and aws_cloudtrail_success(event)


def title(event):
    return f"S3 bucket modified by [{deep_get(event, 'userIdentity', 'arn')}]"


def alert_context(event):
    return aws_rule_context(event)
