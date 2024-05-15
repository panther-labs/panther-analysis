from panther_base_helpers import aws_rule_context

IPSET_ACTIONS = ["CreateIPSet", "UpdateIPSet"]


def rule(event):
    if (
        event.udm("event_source", default="") == "guardduty.amazonaws.com"
        or event.udm("event_source", default="") == "wafv2.amazonaws.com"
    ):
        if event.udm("event_name", default="") in IPSET_ACTIONS:
            return True
    return False


def title(event):
    return "IPSet was modified in " f"[{event.udm('recipient_account_id', default='')}]"


def alert_context(event):
    return aws_rule_context(event)
