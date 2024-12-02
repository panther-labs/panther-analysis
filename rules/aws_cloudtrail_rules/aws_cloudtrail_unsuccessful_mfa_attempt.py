from panther_aws_helpers import aws_rule_context


def rule(event):
    if (
        event.get("eventSource") != "signin.amazonaws.com"
        and event.get("eventName") != "ConsoleLogin"
    ):
        return False

    mfa_used = event.deep_get("additionalEventData", "MFAUsed", default="")
    console_login = event.deep_get("responseElements", "ConsoleLogin", default="")

    if mfa_used == "Yes" and console_login == "Failure":
        return True
    return False


def title(event):
    arn = event.deep_get("userIdenity", "arn", default="No ARN")
    username = event.deep_get("additionalEventData", "UserName", default="No Username")

    return f"Failed MFA login from [{arn}] [{username}]"


def alert_context(event):
    return aws_rule_context(event)
