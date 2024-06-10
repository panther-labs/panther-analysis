from panther_base_helpers import aws_rule_context

EVASION_OPERATIONS = ["BatchUpdateFindings", "DeleteInsight", "UpdateFindings", "UpdateInsight"]


def rule(event):
    if (
        event.udm("event_source", default="") == "securityhub.amazonaws.com"
        and event.udm("event_name", default="") in EVASION_OPERATIONS
    ):
        return True
    return False


def title(event):
    return (
        "SecurityHub Findings have been modified in account: "
        f"[{event.udm('recipient_account_id',default='')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
