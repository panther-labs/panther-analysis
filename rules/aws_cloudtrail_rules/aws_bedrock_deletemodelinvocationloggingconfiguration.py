from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if (
        event.get("eventSource") == "bedrock.amazonaws.com"
        and event.get("eventName") == "DeleteModelInvocationLoggingConfiguration"
        and aws_cloudtrail_success(event)
    ):
        return True
    return False


def title(event):
    user = event.udm("actor_user")
    return f"User [{user}] deleted Bedrock model invocation logging configuration"


def alert_context(event):
    return aws_rule_context(event)
