from panther_base_helpers import aws_rule_context, deep_get


def rule(event):
    # Only check password update changes
    if event.get("eventName") != "PasswordUpdated":
        return False

    # Only check root activity
    if deep_get(event, "userIdentity", "type") != "Root":
        return False

    # Only alert if the login was a success
    return deep_get(event, "responseElements", "PasswordUpdated") == "Success"


def alert_context(event):
    return aws_rule_context(event)
