from panther_base_helpers import aws_rule_context
def rule(event):
    return event.get("log-status") == "SKIPDATA"


def alert_context(event):
    return aws_rule_context(event)
