from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") == "CreateRole"


def alert_context(event):
    context = aws_rule_context(event)
    context["request_rolename"] = event.deep_get(
        "requestParameters", "roleName", default="ROLENAME_NOT_FOUND"
    )
    return context
