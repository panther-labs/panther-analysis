from panther_aws_helpers import aws_rule_context
from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    return event.get("eventName") == "ListIdentities"


def alert_context(event: PantherEvent) -> dict:
    context = aws_rule_context(event)
    context["accountRegion"] = f"{event.get('recipientAccountId')}_{event.get('eventRegion')}"
    return context
