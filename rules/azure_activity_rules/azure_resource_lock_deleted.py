from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

LOCK_DELETE = "MICROSOFT.AUTHORIZATION/LOCKS/DELETE"


def rule(event):
    return event.get("operationName", "").upper() == LOCK_DELETE and azure_activity_success(event)


def title(event):
    resource_id = event.get("resourceId", "")
    lock_name = extract_resource_name_from_id(resource_id, "locks", default="<UNKNOWN_LOCK>")

    return f"Azure resource lock [{lock_name}] deleted"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    lock_name = extract_resource_name_from_id(resource_id, "locks", default="")
    if lock_name:
        context["lock_name"] = lock_name

    # Extract the resource that was protected by the lock
    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        context["resource_group"] = resource_group

    # Check if this is a subscription-level or resource-level lock
    if "/subscriptions/" in resource_id and "/resourceGroups/" not in resource_id:
        context["lock_scope"] = "subscription"
    elif "/resourceGroups/" in resource_id:
        context["lock_scope"] = "resource_group_or_resource"

    return context
