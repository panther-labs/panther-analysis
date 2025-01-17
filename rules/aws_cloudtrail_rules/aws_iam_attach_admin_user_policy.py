from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if not aws_cloudtrail_success(event) or event.get("eventName") != "AttachUserPolicy":
        return False

    policy = event.deep_get("requestParameters", "policyArn", default="POLICY_NOT_FOUND")

    return policy.endswith("AdministratorAccess")


def alert_context(event):
    context = aws_rule_context(event)
    context["request_username"] = event.deep_get(
        "requestParameters", "userName", default="USERNAME_NOT_FOUND"
    )
    return context
