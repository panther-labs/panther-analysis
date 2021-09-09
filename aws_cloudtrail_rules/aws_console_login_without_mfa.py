from panther import lookup_aws_account_name
from panther_base_helpers import deep_get


def rule(event):
    if event.get("eventName") != "ConsoleLogin":
        return False

    additional_event_data = event.get("additionalEventData", {})
    session_context = deep_get(event, "userIdentity", "sessionContext", default={})
    response_elements = event.get("responseElements", {})

    return (
        # Only alert on successful logins
        response_elements.get("ConsoleLogin") == "Success"
        and
        # Where MFA is not in use
        additional_event_data.get("MFAUsed") == "No"
        and
        # Ignoring SSO login events
        not additional_event_data.get("SamlProviderArn")
        and
        # And ignoring logins that were authenticated via a session that was itself
        # authenticated with MFA
        deep_get(session_context, "attributes", "mfaAuthenticated") != "true"
    )


def title(event):
    if deep_get(event, "userIdentity", "type") == "Root":
        user_string = "the root user"
    else:
        user_string = f"user {deep_get(event, 'userIdentity', 'userName')}"
    account_id = event.get("recipientAccountId")
    account_name = lookup_aws_account_name(account_id)
    if account_id == account_name:
        account_string = f"unnamed account ({account_id})"
    else:
        account_string = f"{account_name} account ({account_id})"

    return f"AWS login detected without MFA for [{user_string}] in [{account_string}]"
