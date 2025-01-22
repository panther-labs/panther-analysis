from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "lambda.amazonaws.com"
        and event.get("eventName").startswith("UpdateFunctionCode")
    )


def title(event):
    lambda_name = event.deep_get(
        "responseElements", "functionName", default="LAMBDA_NAME_NOT_FOUND"
    )
    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user', default='USER_NOT_FOUND')}] "
        f"updated Lambda function code for [{lambda_name}]"
    )


def alert_context(event):
    return aws_rule_context(event)
