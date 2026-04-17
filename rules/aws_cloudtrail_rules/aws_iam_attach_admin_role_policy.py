from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if not aws_cloudtrail_success(event) or event.get("eventName") != "AttachRolePolicy":
        return False

    policy = event.deep_get("requestParameters", "policyArn", default="POLICY_NOT_FOUND")

    return policy.endswith("AdministratorAccess")


def alert_context(event):
    context = aws_rule_context(event)
    context["request_rolename"] = event.deep_get(
        "requestParameters", "roleName", default="ROLENAME_NOT_FOUND"
    )
    return context
