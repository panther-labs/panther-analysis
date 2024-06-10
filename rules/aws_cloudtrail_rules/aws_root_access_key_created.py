from panther_base_helpers import aws_rule_context


def rule(event):
    # Only check access key creation events
    if event.udm("event_name") != "CreateAccessKey":
        return False

    # Only root can create root access keys
    if event.udm("user_type") != "Root":
        return False

    # Only alert if the root user is creating an access key for itself
    return event.udm("request_parameters") is None


def alert_context(event):
    return aws_rule_context(event)
