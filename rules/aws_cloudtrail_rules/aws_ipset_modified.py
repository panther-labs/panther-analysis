from panther_base_helpers import aws_rule_context

IPSET_ACTIONS = ["CreateIPSet", "UpdateIPSet"]


def rule(event):
    if (
        event.get("eventSource", "") == "guardduty.amazonaws.com"
        or event.get("eventSource", "") == "wafv2.amazonaws.com"
    ):
        if event.get("eventName", "") in IPSET_ACTIONS:
            return True
    return False


def title(event):
    return "IPSet was modified in " f"[{event.get('recipientAccountId','')}]"


def alert_context(event):
    return aws_rule_context(event)
