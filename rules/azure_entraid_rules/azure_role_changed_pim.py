from panther_azure_helpers import azure_rule_context, azure_success, get_target_name
from panther_base_helpers import deep_walk


def rule(event):
    operation = event.get("operationName", default="")
    if azure_success and "Add member to role in PIM completed" in operation:
        return True

    return False


def title(event):
    operation_name = event.get("operationName", default="")
    actor_name = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default=""
    )
    target_name = get_target_name(event)
    role = deep_walk(
        event, "properties", "targetResources", "displayName", return_val="first", default=""
    )
    return f"{actor_name} added {target_name} as {role} successfully with {operation_name}"


def alert_context(event):
    return azure_rule_context(event)
