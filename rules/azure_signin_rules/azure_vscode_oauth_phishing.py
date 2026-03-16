from panther_azuresignin_helpers import (
    actor_user,
    azure_signin_alert_context,
    azure_signin_success,
    is_sign_in_event,
)

# Visual Studio Code first-party application ID
VSCODE_APP_ID = "aebc6443-996d-45c2-90f0-388ff96faa56"

# Microsoft Graph resource ID
MS_GRAPH_RESOURCE_ID = "00000003-0000-0000-c000-000000000000"


def rule(event):
    if not is_sign_in_event(event) or not azure_signin_success(event):
        return False

    # Check if Visual Studio Code application is being used
    app_id = event.deep_get("properties", "appId", default="")
    user_agent = event.deep_get("properties", "userAgent", default="").lower()
    is_vscode = app_id == VSCODE_APP_ID or "visual studio code" in user_agent

    # Check if accessing Microsoft Graph
    resource_id = event.deep_get("properties", "resourceId", default="")
    resource_name = event.deep_get("properties", "resourceDisplayName", default="").lower()
    accessing_graph = resource_id == MS_GRAPH_RESOURCE_ID or "microsoft graph" in resource_name

    # Alert on VS Code OAuth to Microsoft Graph
    return is_vscode and accessing_graph


def title(event):
    principal = actor_user(event)
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"

    ip_address = event.deep_get("properties", "ipAddress", default="<UNKNOWN_IP>")

    return f"VS Code OAuth to Microsoft Graph: [{principal}] from [{ip_address}]"


def alert_context(event):
    context = azure_signin_alert_context(event)

    # Add OAuth phishing-specific context
    context["app_id"] = event.deep_get("properties", "appId", default="<NO_APP_ID>")
    context["app_display_name"] = event.deep_get("properties", "appDisplayName", default="<NO_APP>")
    context["user_agent"] = event.deep_get("properties", "userAgent", default="<NO_USER_AGENT>")
    context["authentication_protocol"] = event.deep_get(
        "properties", "authenticationProtocol", default="<NO_PROTOCOL>"
    )
    context["token_issuer_type"] = event.deep_get(
        "properties", "tokenIssuerType", default="<NO_ISSUER_TYPE>"
    )
    context["is_interactive"] = event.deep_get("properties", "isInteractive", default=None)

    return context
