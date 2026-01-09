from panther_azuresignin_helpers import (
    azure_signin_alert_context,
    azure_signin_success,
    is_sign_in_event,
)


def rule(event):
    # Check for sign-in events
    if not is_sign_in_event(event) or not azure_signin_success(event):
        return False

    # Check for ROPC authentication protocol
    auth_protocol = event.deep_get("properties", "authenticationProtocol", default="").lower()
    if auth_protocol != "ropc":
        return False

    auth_requirement = event.deep_get("properties", "authenticationRequirement", default="").lower()

    # Only alert on no MFA
    if auth_requirement != "singlefactorauthentication":
        return False

    # Check user type for Member account
    user_type = event.deep_get("properties", "userType", default="").lower()
    if user_type and user_type != "member":
        return False

    return True


def title(event):
    user_principal_name = event.deep_get(
        "properties", "userPrincipalName", default="<UNKNOWN_USER>"
    )
    source_ip = event.deep_get("properties", "ipAddress", default="<UNKNOWN_IP>")
    app_display_name = event.deep_get("properties", "appDisplayName", default="<UNKNOWN_APP>")

    return (
        f"ROPC Login Without MFA: User [{user_principal_name}] authenticated via "
        f"ROPC protocol from IP [{source_ip}] to app [{app_display_name}]"
    )


def alert_context(event):
    context = azure_signin_alert_context(event)

    # Add ROPC-specific fields
    fields = {
        "authentication_protocol": ("properties", "authenticationProtocol", "<NO_PROTOCOL>"),
        "authentication_requirement": (
            "properties",
            "authenticationRequirement",
            "<NO_REQUIREMENT>",
        ),
        "user_type": ("properties", "userType", "<NO_USER_TYPE>"),
        "app_display_name": ("properties", "appDisplayName", "<NO_APP>"),
        "app_id": ("properties", "appId", "<NO_APP_ID>"),
        "client_app_used": ("properties", "clientAppUsed", "<NO_CLIENT_APP>"),
        "user_agent": ("properties", "userAgent", "<NO_USER_AGENT>"),
        "is_interactive": ("properties", "isInteractive", None),
        "conditional_access_status": ("properties", "conditionalAccessStatus", "<NO_CA_STATUS>"),
        "device_detail_browser": ("properties", "deviceDetail", "browser", "<NO_BROWSER>"),
        "device_detail_os": ("properties", "deviceDetail", "operatingSystem", "<NO_OS>"),
    }

    for key, (*path, default) in fields.items():
        context[key] = event.deep_get(*path, default=default)

    return context
