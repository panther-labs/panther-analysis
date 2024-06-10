from panther_base_helpers import aws_rule_context


def rule(event):
    if (
        event.udm("event_source") != "signin.amazonaws.com"
        and event.udm("event_name") != "ConsoleLogin"
    ):
        return False

    mfa_used = event.udm("mfa_used")
    console_login = event.udm("login_status")

    if mfa_used == "Yes" and console_login == "Failure":
        return True
    return False


def title(event):
    arn = event.udm("user_arn")
    username = event.udm("actor_user")

    return f"Failed MFA login from [{arn}] [{username}]"


def alert_context(event):
    return aws_rule_context(event)
