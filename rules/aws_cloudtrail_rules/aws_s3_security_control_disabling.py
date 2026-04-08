from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if not aws_cloudtrail_success(event):
        return False
    if event.get("eventSource") != "s3.amazonaws.com":
        return False

    event_name = event.get("eventName")

    if event_name == "PutBucketLogging":
        return event.deep_get("requestParameters", "logging") == ""

    if event_name == "PutBucketVersioning":
        status = event.deep_get(
            "requestParameters", "VersioningConfiguration", "Status", default=""
        )
        mfa_delete = event.deep_get(
            "requestParameters", "VersioningConfiguration", "MfaDelete", default=""
        )
        return status in ("Suspended", "Disabled") or mfa_delete == "Disabled"

    return False


def unique(event):
    if event.get("eventName") == "PutBucketLogging":
        return "logging_disabled"

    # PutBucketVersioning — both versioning and MFA delete can be disabled in a single API call.
    # When that happens this event contributes only one unique value, capping the maximum
    # distinct values at 2 (this + logging_disabled). Threshold is set to 2 so the rule
    # fires correctly even when all three controls are disabled via just two API calls.
    status = event.deep_get("requestParameters", "VersioningConfiguration", "Status", default="")
    mfa_delete = event.deep_get(
        "requestParameters", "VersioningConfiguration", "MfaDelete", default=""
    )
    versioning_disabled = status in ("Suspended", "Disabled")
    mfa_disabled = mfa_delete == "Disabled"

    if versioning_disabled and mfa_disabled:
        return "versioning_and_mfa_disabled"
    if versioning_disabled:
        return "versioning_suspended"
    return "mfa_delete_disabled"


def dedup(event):
    bucket = event.deep_get("requestParameters", "bucketName", default="UNKNOWN_BUCKET")
    actor = event.deep_get("userIdentity", "arn", default="UNKNOWN_ACTOR")
    return f"{bucket}:{actor}"


def title(event):
    bucket = event.deep_get("requestParameters", "bucketName", default="UNKNOWN_BUCKET")
    actor = event.udm("actor_user")
    return f"[AWS.S3] Multiple security controls disabled on bucket [{bucket}] by [{actor}]"


def alert_context(event):
    context = aws_rule_context(event)
    context["bucketName"] = event.deep_get(
        "requestParameters", "bucketName", default="UNKNOWN_BUCKET"
    )
    return context
