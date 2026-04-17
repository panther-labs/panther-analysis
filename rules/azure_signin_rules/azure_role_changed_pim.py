from panther_msft_helpers import azure_rule_context, azure_success, get_target_name


def rule(event):
    operation = event.get("operationName", default="")
    if azure_success(event) and "Add member to role in PIM completed" in operation:
        return True

    return False


def title(event):
    operation_name = event.get("operationName", default="<UNKNOWN OPERATION>")
    actor_name = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default="<UNKNOWN USER>"
    )
    target_name = get_target_name(event)
    role = event.deep_walk(
        "properties", "targetResources", "displayName", return_val="first", default="<UNKNOWN_ROLE>"
    )
    return f"{actor_name} added {target_name} as {role} successfully with {operation_name}"


def dedup(event):
    # Ensure every event is a separate alert
    return event.get("p_row_id", "<UNKNOWN_ROW_ID>")


def alert_context(event):
    return azure_rule_context(event)
