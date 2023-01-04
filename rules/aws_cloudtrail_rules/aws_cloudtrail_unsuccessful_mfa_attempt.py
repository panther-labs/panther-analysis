from panther_base_helpers import aws_rule_context, deep_get


def rule(event):

    if (
        event.get("eventSource") != "signin.amazonaws.com"
        and event.get("eventName") != "ConsoleLogin"
    ):
        return False

    mfa_used = deep_get(event, "additionalEventData", "MFAUsed", default="")
    console_login = deep_get(event, "responseElements", "ConsoleLogin", default="")

    if mfa_used == "Yes" and console_login == "Failure":
        return True
    return False


def title(event):

    arn = deep_get(event, "userIdenity", "arn", default="No ARN")
    username = deep_get(event, "userIdentity", "userName", default="No Username")

    return f"Failed MFA login from [{arn}] [{username}]"


def alert_context(event):
    return aws_rule_context(event)
