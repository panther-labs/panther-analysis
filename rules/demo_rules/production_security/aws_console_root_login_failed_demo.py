from panther_aws_helpers import aws_rule_context, lookup_aws_account_name


def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.deep_get("userIdentity", "type") == "Root"
        and event.deep_get("responseElements", "ConsoleLogin") == "Failure"
    )


def title(event):
    return (
        f"AWS root login failed from [{event.get('sourceIPAddress')}] in account "
        f"[{lookup_aws_account_name(event.get('recipientAccountId'))}]"
    )


def alert_context(event):
    return aws_rule_context(event)
