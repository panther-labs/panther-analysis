from panther import lookup_aws_account_name
from panther_base_helpers import deep_get


def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") == "IAMUser"
        and deep_get(event, "responseElements", "ConsoleLogin") == "Failure"
    )


def title(event):
    return f"AWS logins failed in account [{lookup_aws_account_name(event.get('recipientAccountId'))}]"
