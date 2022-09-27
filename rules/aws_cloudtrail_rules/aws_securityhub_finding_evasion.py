from panther_base_helpers import aws_rule_context

EVASION_OPERATIONS = ["BatchUpdateFindings", "DeleteInsight", "UpdateFindings", "UpdateInsight"]


def rule(event):
    if (
        event.get("eventSource", "") == "securityhub.amazonaws.com"
        and event.get("eventName", "") in EVASION_OPERATIONS
    ):
        return True
    return False


def title(event):
    return (
        "SecurityHub Findings have been modified in account: "
        f"[{event.get('recipientAccountId','')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
