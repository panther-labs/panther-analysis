from panther_aws_helpers import aws_cloudtrail_success


def is_sso_like_role(event):
    # Check for SSO-like role in sessionIssuer ARN or role name
    session_issuer_arn = event.deep_get(
        "userIdentity", "sessionContext", "sessionIssuer", "arn", default=""
    )
    role_name = event.deep_get(
        "userIdentity", "sessionContext", "sessionIssuer", "userName", default=""
    )
    return (
        "aws-reserved/sso.amazonaws.com" in session_issuer_arn
        or "AWSReservedSSO" in role_name
        or "AWSReservedSSO" in session_issuer_arn
    )


def rule(event):
    return (
        event.get("eventSource") == "s3.amazonaws.com"
        and event.get("eventName", "").startswith("DeleteBucket")
        and event.get("awsRegion") == "us-west-2"
        and aws_cloudtrail_success(event)
        and is_sso_like_role(event)
    )


def title(event):
    actor = event.udm("actor_user") or "unknown actor"
    bucket = event.deep_get("requestParameters", "bucketName", default="unknown bucket")
    return f"SSO-like role [{actor}] deleted S3 bucket [{bucket}] in us-west-2"


def alert_context(event):
    return {
        "actor": event.udm("actor_user") or "",
        "bucket": event.deep_get("requestParameters", "bucketName", default=""),
        "timestamp": event.get("eventTime", ""),
        "source_ip": event.udm("source_ip"),
        "user_agent": event.udm("user_agent"),
        "action": event.get("eventName", ""),
        "region": event.get("awsRegion", ""),
    }


def runbook(event):
    actor = event.udm("actor_user") or "unknown actor"
    bucket = event.deep_get("requestParameters", "bucketName", default="unknown bucket")
    return (
        f"1. Review CloudTrail events for [{actor}] and S3 bucket [{bucket}] in us-west-2 "
        f"around the time of this alert.\n"
        f"2. Confirm if the SSO role deletion was expected and authorized.\n"
        f"3. Investigate any follow-up actions performed by the SSO role.\n"
        f"4. If unauthorized, restore the bucket if possible and review SSO permissions.\n"
    )
