from panther_aws_helpers import aws_rule_context


def rule(event):
    # Only check access key creation events
    if event.get("eventName") != "CreateAccessKey":
        return False

    # Only root can create root access keys
    if event.deep_get("userIdentity", "type") != "Root":
        return False

    # Only alert if the root user is creating an access key for itself
    return event.get("requestParameters") is None


def alert_context(event):
    return aws_rule_context(event)
