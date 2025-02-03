from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

ADD_PERMISSION_EVENTS = {
    "AddPermission20150331",
    "AddPermission20150331v2",
}


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "lambda.amazonaws.com"
        and event.get("eventName") in ADD_PERMISSION_EVENTS
    )


def title(event):
    lambda_name = event.deep_get(
        "responseElements", "functionName", default="LAMBDA_NAME_NOT_FOUND"
    )
    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user')}] "
        f"added permission to Lambda function [{lambda_name}]"
    )


def alert_context(event):
    return aws_rule_context(event)
