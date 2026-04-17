from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

NSG_OPERATIONS = [
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/JOIN/ACTION",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/PROVIDERS/MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
]


def rule(event):
    return event.get("operationName", "").upper() in NSG_OPERATIONS and azure_activity_success(
        event
    )


def title(event):
    operation = event.get("operationName", "").upper()

    # Determine action description based on operation
    if "DELETE" in operation:
        action = "deleted"
    elif "WRITE" in operation:
        action = "modified"
    elif "JOIN" in operation:
        action = "joined"
    else:
        action = "configuration changed for"

    # Determine resource type
    if "SECURITYRULES" in operation:
        resource_type = "Network Security Rule"
    elif "DIAGNOSTICSETTINGS" in operation:
        resource_type = "NSG Diagnostic Settings"
    else:
        resource_type = "Network Security Group"

    return f"Azure {resource_type} {action}"


def alert_context(event):
    return azure_activity_alert_context(event)
