from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

FIREWALL_POLICY_DELETE_OPERATION = "MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE"


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() == FIREWALL_POLICY_DELETE_OPERATION and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    policy_name = extract_resource_name_from_id(
        resource_id, "firewallPolicies", default="<UNKNOWN_POLICY>"
    )

    return f"Azure Firewall Policy Deleted: [{policy_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    policy_name = extract_resource_name_from_id(resource_id, "firewallPolicies", default="")
    if policy_name:
        context["firewall_policy_name"] = policy_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    return context
