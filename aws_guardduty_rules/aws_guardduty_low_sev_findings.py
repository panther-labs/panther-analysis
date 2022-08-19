from panther_base_helpers import aws_rule_context
def rule(event):
    return 0.1 <= float(event.get("severity", 0)) <= 3.9


def dedup(event):
    return event.get("id")


def title(event):
    return event.get("title")


def alert_context(event):
    return aws_rule_context(event)
