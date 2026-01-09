import json

from panther_azuresignin_helpers import azure_signin_alert_context, azure_signin_success
from panther_detection_helpers.caching import add_to_string_set

RULE_ID = "Azure.SignIn.GraphSessionMultipleIPs"

# Whitelisted application IDs (common Microsoft services that may legitimately use multiple IPs)
WHITELISTED_APP_IDS = {
    "00000003-0000-0ff1-ce00-000000000000",  # Office 365
    "00000006-0000-0ff1-ce00-000000000000",  # Office 365 Exchange Online
    "00b41c95-dab0-4487-9791-b9d2c32c80f2",  # Office 365 Management APIs
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264",  # Microsoft Teams
    "5e3ce6c0-2b1f-4285-8d4b-75ee78787346",  # Microsoft Teams Services
    "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",  # Microsoft Teams - Device Profile Service
    "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive SyncEngine
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "ea5a67f6-b6f3-4338-b240-c655ddc3cc8e",  # Microsoft Edge Insider Addons
    "ecd6b820-32c2-49b6-98a6-444530e5a77a",  # Edge Remote Settings
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34",  # Microsoft Edge
    "2793995e-0a7d-40d7-bd35-6968ba142197",  # Microsoft Defender for Cloud
    "18fbca16-2224-45f6-85b0-f7bf2b39b3f3",  # Microsoft Docs
    "98db8bd6-0cc0-4e67-9de5-f187f1cd1b41",  # Microsoft Substrate Management
}


def rule(event):
    resource_display_name = event.deep_get("properties", "resourceDisplayName", default="")
    session_id = event.deep_get("properties", "sessionId", default="")
    user_principal_name = event.deep_get("properties", "userPrincipalName", default="")
    source_ip = event.deep_get("properties", "ipAddress", default="")
    app_id = event.deep_get("properties", "appId", default="")

    # Skip if not Microsoft Graph access or whitelisted applications
    if "Microsoft Graph" not in resource_display_name or app_id in WHITELISTED_APP_IDS:
        return False

    # Skip if essential fields are missing or failed attempts
    if (
        not session_id
        or not user_principal_name
        or not source_ip
        or not azure_signin_success(event)
    ):
        return False

    # Track IPs per session
    cache_key = f"{session_id}-{user_principal_name}-{RULE_ID}"
    ip_set = add_to_string_set(cache_key, [source_ip])

    # Handle unit test mocks
    if isinstance(ip_set, str):
        ip_set = json.loads(ip_set) if ip_set else []

    # Alert if multiple IPs are used for the same session
    return len(ip_set) >= 2


def title(event):
    user_principal_name = event.deep_get(
        "properties", "userPrincipalName", default="<UNKNOWN_USER>"
    )
    session_id = event.deep_get("properties", "sessionId", default="<UNKNOWN_SESSION>")

    return (
        f"Microsoft Graph Session Access from Multiple IPs: "
        f"User [{user_principal_name}] in "
        f"session [{session_id}]"
    )


def alert_context(event):
    context = azure_signin_alert_context(event)

    # Add Graph access specific context
    context["session_id"] = event.deep_get("properties", "sessionId", default="<NO_SESSION>")
    context["app_display_name"] = event.deep_get("properties", "appDisplayName", default="<NO_APP>")
    context["app_id"] = event.deep_get("properties", "appId", default="<NO_APP_ID>")
    context["resource_display_name"] = event.deep_get(
        "properties", "resourceDisplayName", default="<NO_RESOURCE>"
    )
    context["authentication_protocol"] = event.deep_get(
        "properties", "authenticationProtocol", default="<NO_PROTOCOL>"
    )
    context["conditional_access_status"] = event.deep_get(
        "properties", "conditionalAccessStatus", default="<NO_CA_STATUS>"
    )
    context["is_interactive"] = event.deep_get("properties", "isInteractive", default=None)
    context["user_agent"] = event.deep_get("properties", "userAgent", default="<NO_USER_AGENT>")

    return context
