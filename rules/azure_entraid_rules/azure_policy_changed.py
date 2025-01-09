from panther_azure_helpers import azure_rule_context, azure_success
from panther_base_helpers import deep_walk

POLICY_OPERATION = "policy"

IGNORE_ACTIONS = ["Add", "Added"]


def rule(event):
    operation = event.get("operationName", default="")
    if not azure_success or not operation.endswith(POLICY_OPERATION):
        return False
    # Ignore added policies
    if any(
        (
            event.deep_get("properties", "operationName", default="").startswith(ignore)
            for ignore in IGNORE_ACTIONS
        )
    ):
        return False

    return True


def title(event):
    operation_name = event.get("operationName", default="")
    actor_name = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default=""
    )
    policy = deep_walk(event, "properties", "targetResources", "displayName", default="")

    return f"{operation_name} by {actor_name} on the policy {policy}"


def alert_context(event):
    return azure_rule_context(event)
