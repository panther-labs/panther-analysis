from panther_base_helpers import aws_rule_context, deep_get
from panther_default import lookup_aws_account_name


def rule(event):
    additional_event_data = event.get("additionalEventData", {})
    return (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") != "AssumedRole"
        and not additional_event_data.get("SamlProviderArn")
    )


def title(event):
    return (
        f"AWS logins without SAML in account "
        f"[{lookup_aws_account_name(event.get('recipientAccountId'))}]"
    )


def alert_context(event):
    return aws_rule_context(event)
