from panther_aws_helpers import aws_rds_context


def rule(event):
    if event.get("eventSource") != "rds.amazonaws.com":
        return False
    if event.get("eventName") != "StopActivityStream":
        return False
    return event.deep_get("errorCode") is None


def title(event):
    db_identifier = event.deep_get("requestParameters", "resourceArn", default="<UNKNOWN>").split(
        ":"
    )[-1]
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity", "principalId", default="<UNKNOWN_USER>"
    )
    return f"RDS Activity Stream Stopped: [{db_identifier}] by [{user}]"


def alert_context(event):
    context = aws_rds_context(event)
    context["resource_arn"] = event.deep_get("requestParameters", "resourceArn", default="N/A")
    context["apply_immediately"] = event.deep_get(
        "requestParameters", "applyImmediately", default="N/A"
    )
    return context
