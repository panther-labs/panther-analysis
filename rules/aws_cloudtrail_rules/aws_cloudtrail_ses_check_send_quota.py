from panther_aws_helpers import aws_rule_context
from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    if event.get("eventName") == "GetSendQuota":
        # Exclude AWS Trusted Advisor automated checks
        role_name = event.deep_get("userIdentity", "sessionContext", "sessionIssuer", "userName")
        if role_name == "AWSServiceRoleForTrustedAdvisor":
            return False
        return True
    return False


def alert_context(event: PantherEvent) -> dict:
    context = aws_rule_context(event)
    context["accountRegion"] = f"{event.get('recipientAccountId')}_{event.get('eventRegion')}"
    return context
