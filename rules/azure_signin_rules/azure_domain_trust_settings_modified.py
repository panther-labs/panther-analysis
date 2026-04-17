def rule(event):
    operation_name = event.get("operationName", "")

    # Branch 1: For "Set federation settings on domain" any change is suspicious
    if "set federation settings on domain" in operation_name.lower():
        return True

    # Branch 2: For "Set domain authentication" check if LiveType property changed to Federated
    if "set domain authentication" in operation_name.lower():
        display_names = event.deep_walk(
            "properties", "targetResources", "modifiedProperties", "displayName", default=[]
        )
        new_values = event.deep_walk(
            "properties", "targetResources", "modifiedProperties", "newValue", default=[]
        )

        # Ensure we have lists (deep_walk returns single value if only one result)
        if not isinstance(display_names, list):
            display_names = [display_names] if display_names else []
        if not isinstance(new_values, list):
            new_values = [new_values] if new_values else []

        if len(display_names) != len(new_values):
            # Lists have different lengths; check all values with consistent approach
            if "LiveType" in display_names and any(
                isinstance(val, str) and "Federated" in val for val in new_values
            ):
                return True
            return False

        # Check if the same property has displayName="LiveType" AND newValue contains "Federated"
        for display_name, new_value in zip(display_names, new_values):
            if (
                display_name == "LiveType"
                and isinstance(new_value, str)
                and "Federated" in new_value
            ):
                return True

    return False


def title(event):
    actor = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default="<UNKNOWN_ACTOR>"
    )

    return f"Domain Federation Trust Settings Modified by [{actor}] "


def alert_context(event):
    context = {}

    # Add federation-specific context
    context["operation_name"] = event.get("operationName", "<NO_OPERATION>")
    context["activity_display_name"] = event.deep_get(
        "properties", "activityDisplayName", default="<NO_ACTIVITY>"
    )
    context["category"] = event.get("category", "<NO_CATEGORY>")

    # Add initiator details
    context["initiator_user_id"] = event.deep_get(
        "properties", "initiatedBy", "user", "id", default="<NO_USER_ID>"
    )
    context["initiator_display_name"] = event.deep_get(
        "properties", "initiatedBy", "user", "displayName", default="<NO_DISPLAY_NAME>"
    )
    context["initiator_ip"] = event.deep_get(
        "properties", "initiatedBy", "user", "ipAddress", default="<NO_IP>"
    )

    return context
