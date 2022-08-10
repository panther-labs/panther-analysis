from panther import aws_cloudtrail_success
from panther_base_helpers import deep_get, aws_rule_context


def rule(event):
    # Capture DeleteBucket, DeleteBucketPolicy, DeleteBucketWebsite
    return event.get("eventName").startswith("DeleteBucket") and aws_cloudtrail_success(event)


def helper_strip_role_session_id(user_identity_arn):
    # The Arn structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split("/")
    if arn_parts:
        return "/".join(arn_parts[:2])
    return user_identity_arn


def dedup(event):
    user_identity = event.get("userIdentity", {})
    if user_identity.get("type") == "AssumedRole":
        return helper_strip_role_session_id(user_identity.get("arn", ""))
    return user_identity.get("arn")


def title(event):
    return f"{deep_get(event, 'userIdentity', 'type')} [{dedup(event)}] destroyed a bucket"


def alert_context(event):
    return aws_rule_context(event)
