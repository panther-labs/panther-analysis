from panther_base_helpers import aws_rule_context
from panther_default import lookup_aws_account_name


def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.deep_get("userIdentity", "type") == "IAMUser"
        and event.deep_get("responseElements", "ConsoleLogin") == "Failure"
    )


def title(event):
    return (
        f"AWS logins failed in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"
    )


def alert_context(event):
    return aws_rule_context(event)
