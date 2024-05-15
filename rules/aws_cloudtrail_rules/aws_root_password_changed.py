from panther_base_helpers import aws_rule_context


def rule(event):
    # Only check password update changes
    if event.udm("event_name") != "PasswordUpdated":
        return False

    # Only check root activity
    if event.udm("user_type") != "Root":
        return False

    # Only alert if the login was a success
    return event.udm("password_updated") == "Success"


def alert_context(event):
    return aws_rule_context(event)
