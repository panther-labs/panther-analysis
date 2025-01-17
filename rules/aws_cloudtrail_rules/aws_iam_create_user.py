from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") == "CreateUser"


def alert_context(event):
    context = aws_rule_context(event)
    context["request_username"] = event.deep_get(
        "requestParameters", "userName", default="USERNAME_NOT_FOUND"
    )
    return context
