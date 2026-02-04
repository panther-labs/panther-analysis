import json

from panther_azuresignin_helpers import azure_signin_alert_context, azure_signin_success
from panther_detection_helpers.caching import add_to_string_set

RULE_ID = "Azure.SignIn.GraphSessionMultipleIPs"

# Whitelisted application IDs (common Microsoft services that may legitimately use multiple IPs)
WHITELISTED_APP_IDS = {
    # Office 365 / Microsoft 365
    "00000003-0000-0ff1-ce00-000000000000",  # Office 365
    "00000006-0000-0ff1-ce00-000000000000",  # Office 365 Exchange Online
    "00b41c95-dab0-4487-9791-b9d2c32c80f2",  # Office 365 Management APIs
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    # Microsoft Teams
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264",  # Microsoft Teams
    "5e3ce6c0-2b1f-4285-8d4b-75ee78787346",  # Microsoft Teams Services
    "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",  # Microsoft Teams - Device Profile Service
    # OneDrive
    "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive SyncEngine
    # Microsoft Edge
    "ea5a67f6-b6f3-4338-b240-c655ddc3cc8e",  # Microsoft Edge Insider Addons
    "ecd6b820-32c2-49b6-98a6-444530e5a77a",  # Edge Remote Settings
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34",  # Microsoft Edge
    # Azure Infrastructure Services
    "797f4846-ba00-4fd7-ba43-dac1f8f63013",  # Azure Resource Manager
    "8edd93e1-2103-40b4-bd70-6e34e586362d",  # Windows Azure Security Resource Provider
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",  # Azure Portal
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Microsoft Azure CLI
    "4962773b-9cdb-44cf-a8bf-237846a00ab7",  # Microsoft.EventGrid
    # Security & Threat Protection Services
    "fc780465-2017-40d4-a0c5-307022471b92",  # WindowsDefenderATP
    "8ee8fdad-f234-4243-8f3b-15c294843740",  # Microsoft Threat Protection
    "2793995e-0a7d-40d7-bd35-6968ba142197",  # Microsoft Defender for Cloud
    "3f6aecb4-6dbf-4e45-9141-440abdced562",  # PROD Microsoft Defender For Cloud XDR
    "7b7531ad-5926-4f2d-8a1d-38495ad33e17",  # Azure Advanced Threat Protection
    "df77edef-903d-416b-bcc0-cc8b91af54ea",  # Defender for IoT
    "8b3391f4-af01-4ee8-b4ea-9871b2499735",  # O365 Secure Score
    # Microsoft Graph & Identity Services
    "f8f7a2aa-e116-4ba6-8aea-ca162cfa310d",  # Microsoft Graph Connectors Core
    "01fc33a7-78ba-4d2f-a4b7-768e336e890e",  # MS-PIM (Privileged Identity Management)
    "bd11ca0f-4fd6-4bb7-a259-4a36693b6e13",  # MCAPI AAD Bridge Service
    "abc63b55-0325-4305-9e1e-3463b182a6dc",  # TenantSearchProcessors
    "eace8149-b661-472f-b40d-939f89085bd4",  # Substrate Instant Revocation Pipeline
    "b46c3ac5-9da6-418f-a849-0a07a10b3c6c",  # Cloud Infrastructure Entitlement Management
    "0469d4cd-df37-4d93-8a61-f8c75b809164",  # Policy Administration Service
    # Other Microsoft Services
    "18fbca16-2224-45f6-85b0-f7bf2b39b3f3",  # Microsoft Docs
    "98db8bd6-0cc0-4e67-9de5-f187f1cd1b41",  # Microsoft Substrate Management
    # Panther Integrations (distributed infrastructure)
    "6821c7a6-ae62-49ba-8669-3f2e72d8d803",  # GL - Panther Graph Integration
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

    is_interactive = event.deep_get("properties", "isInteractive", default=True)
    if not is_interactive:
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
