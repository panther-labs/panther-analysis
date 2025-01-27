from panther_msft_helpers import azure_rule_context, azure_success

POLICY_OPERATION = "policy"

IGNORE_ACTIONS = ["Add", "Added"]


def rule(event):
    operation = event.get("operationName", default="")
    if not azure_success(event) or not operation.endswith(POLICY_OPERATION):
        return False
    # Ignore added policies
    if any((operation.startswith(ignore) for ignore in IGNORE_ACTIONS)):
        return False

    return True


def title(event):
    operation_name = event.get("operationName", default="")
    actor_name = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default=""
    )
    policy = event.deep_walk("properties", "targetResources", "displayName", default="")

    return f"{operation_name} by {actor_name} on the policy {policy}"


def alert_context(event):
    return azure_rule_context(event)
