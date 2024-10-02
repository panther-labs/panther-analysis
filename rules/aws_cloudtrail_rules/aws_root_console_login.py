from panther_base_helpers import aws_rule_context


def rule(event):
    # Only check console logins
    if event.get("eventName") != "ConsoleLogin":
        return False

    # Only check root activity
    if event.deep_get("userIdentity", "type") != "Root":
        return False

    # Only alert if the login was a success
    return event.deep_get("responseElements", "ConsoleLogin") == "Success"


def alert_context(event):
    return aws_rule_context(event)
