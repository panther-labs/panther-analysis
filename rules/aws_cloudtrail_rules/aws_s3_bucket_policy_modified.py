from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

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
    return f"S3 bucket modified by [{event.deep_get('userIdentity', 'arn')}]"


def alert_context(event):
    return aws_rule_context(event)
