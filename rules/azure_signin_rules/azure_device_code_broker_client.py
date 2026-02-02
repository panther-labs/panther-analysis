from panther_azuresignin_helpers import (
    azure_signin_alert_context,
    azure_signin_success,
    is_sign_in_event,
)

# Microsoft Broker Client Application ID
BROKER_CLIENT_APP_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"


def rule(event):
    if not is_sign_in_event(event) or not azure_signin_success(event):
        return False

    auth_protocol = event.deep_get("properties", "authenticationProtocol", default="").lower()
    if auth_protocol != "devicecode":
        return False

    app_id = event.deep_walk(
        "properties", "conditionalAccessAudiences", "applicationId", default=""
    )

    # deep_walk returns a list if multiple values found, or a string if one value
    if isinstance(app_id, list):
        return BROKER_CLIENT_APP_ID in app_id
    return BROKER_CLIENT_APP_ID == app_id


def title(event):
    user_principal_name = event.deep_get(
        "properties", "userPrincipalName", default="<UNKNOWN_USER>"
    )
    source_ip = event.deep_get("properties", "ipAddress", default="<UNKNOWN_IP>")

    return (
        f"Device Code Authentication with Broker Client: User [{user_principal_name}] "
        f"from IP [{source_ip}]"
    )


def alert_context(event):
    context = azure_signin_alert_context(event)
    return context
