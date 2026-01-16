def rule(event):
    operation_name = event.get("operationName", "")

    if "authentication methods policy update" not in operation_name.lower():
        return False

    old_values = event.deep_walk(
        "properties", "targetResources", "modifiedProperties", "oldValue", default=[]
    )
    new_values = event.deep_walk(
        "properties", "targetResources", "modifiedProperties", "newValue", default=[]
    )

    # Ensure we have lists
    if not isinstance(old_values, list):
        old_values = [old_values] if old_values else []
    if not isinstance(new_values, list):
        new_values = [new_values] if new_values else []

    if len(old_values) != len(new_values):
        # Lists have different lengths; check all values to be safe
        for value in old_values + new_values:
            if isinstance(value, str) and "discoveryUrl" in value:
                return True
        return False

    for old_value, new_value in zip(old_values, new_values):
        if (
            isinstance(old_value, str)
            and isinstance(new_value, str)
            and "discoveryUrl" in old_value
            and "discoveryUrl" in new_value
        ):
            if old_value != new_value:
                return True

    return False


def title(event):
    actor = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default="<UNKNOWN_ACTOR>"
    )
    return f"Authentication Methods Policy OIDC Discovery URL Changed by [{actor}]"


def alert_context(event):
    context = {}

    context["operation_name"] = event.get("operationName", "<NO_OPERATION>")
    context["activity_display_name"] = event.deep_get(
        "properties", "activityDisplayName", default="<NO_ACTIVITY>"
    )
    context["category"] = event.get("category", "<NO_CATEGORY>")

    context["initiator_user_id"] = event.deep_get(
        "properties", "initiatedBy", "user", "id", default="<NO_USER_ID>"
    )
    context["initiator_display_name"] = event.deep_get(
        "properties", "initiatedBy", "user", "displayName", default="<NO_DISPLAY_NAME>"
    )
    context["initiator_ip"] = event.deep_get(
        "properties", "initiatedBy", "user", "ipAddress", default="<NO_IP>"
    )

    # Extract OIDC discovery URL changes
    old_values = event.deep_walk(
        "properties", "targetResources", "modifiedProperties", "oldValue", default=[]
    )
    new_values = event.deep_walk(
        "properties", "targetResources", "modifiedProperties", "newValue", default=[]
    )

    if not isinstance(old_values, list):
        old_values = [old_values] if old_values else []
    if not isinstance(new_values, list):
        new_values = [new_values] if new_values else []

    for old_value, new_value in zip(old_values, new_values):
        if (isinstance(old_value, str) and "discoveryUrl" in old_value) or (
            isinstance(new_value, str) and "discoveryUrl" in new_value
        ):
            context["old_discovery_url"] = old_value
            context["new_discovery_url"] = new_value
            break

    return context
