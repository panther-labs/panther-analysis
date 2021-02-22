from panther import lookup_aws_account_name
from panther_base_helpers import deep_get


def rule(event):
    additional_event_data = event.get("additionalEventData", {})
    return (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") != "AssumedRole"
        and not additional_event_data.get("SamlProviderArn")
    )


def title(event):
    return "AWS logins without SAML in account [{}]".format(
        lookup_aws_account_name(event.get("recipientAccountId"))
    )
