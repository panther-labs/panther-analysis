from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

FIREWALL_POLICY_DELETE_OPERATION = "MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == FIREWALL_POLICY_DELETE_OPERATION and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    policy_name = "<UNKNOWN_POLICY>"
    if resource_id:
        parts = resource_id.split("/")
        if "firewallPolicies" in parts:
            try:
                policy_name = parts[parts.index("firewallPolicies") + 1]
            except (IndexError, ValueError):
                pass

    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")
    return f"Azure Firewall Policy Deleted: [{policy_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "firewallPolicies" in parts:
            try:
                context["firewall_policy_name"] = parts[parts.index("firewallPolicies") + 1]
            except (IndexError, ValueError):
                pass

    return context
