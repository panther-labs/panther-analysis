from panther_aws_helpers import aws_rule_context


def rule(event):
    additional_event_data = event.get("additionalEventData", {})
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.deep_get("userIdentity", "type") != "AssumedRole"
        and not additional_event_data.get("SamlProviderArn")
    )


def title(event):
    return f"AWS logins without SAML in account " f"[{event.get('recipientAccountId')}]"


def alert_context(event):
    return aws_rule_context(event)
