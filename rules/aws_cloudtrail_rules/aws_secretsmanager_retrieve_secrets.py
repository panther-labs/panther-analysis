from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if (
        event.get("eventName") == "GetSecretValue"
        and not aws_cloudtrail_success(event)
        and event.get("errorCode") == "AccessDenied"
    ):
        return True
    return False


def title(event):
    user = event.udm("actor_user")
    return f"[{user}] is not authorized to retrieve secrets from AWS Secrets Manager"


def alert_context(event):
    return aws_rule_context(event) | {
        "errorCode": event.get("errorCode"),
        "errorMessage": event.get("errorMessage"),
    }
