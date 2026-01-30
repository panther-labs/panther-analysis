def rule(event):

    operation_name = event.get("operationName", "")
    result = event.get("result", "").lower()
    return all(
        [
            "User has elevated their access to User Access Administrator" in operation_name,
            result == "success",
        ]
    )


def title(event):
    actor = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default="<UNKNOWN_ACTOR>"
    )

    return f"User Elevated to User Access Administrator Role: [{actor}]"


def alert_context(event):
    context = {}

    context["tenantId"] = event.get("tenantId", "<NO_TENANTID>")
    context["operation_name"] = event.get("operationName", "<NO_OPERATION>")
    context["category"] = event.get("category", "<NO_CATEGORY>")
    context["result"] = event.get("result", "<NO_RESULT>")

    # Initiator details
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
