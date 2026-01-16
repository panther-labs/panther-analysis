CREDENTIAL_OPERATION = "add service principal credentials"


def rule(event):
    # Check for service principal credential addition operations
    operation_name = event.get("operationName", "").lower()
    activity_display_name = event.deep_get("properties", "activityDisplayName", default="").lower()

    return CREDENTIAL_OPERATION in operation_name or CREDENTIAL_OPERATION in activity_display_name


def title(event):
    actor = event.deep_get(
        "properties", "initiatedBy", "user", "userPrincipalName", default="<UNKNOWN_ACTOR>"
    )

    # Get service principal name from target resources
    service_principal = "<UNKNOWN_SP>"
    target_resources = event.deep_get("properties", "targetResources", default=[])
    for resource in target_resources or []:
        if resource.get("type") in ["ServicePrincipal", "Application"]:
            service_principal = resource.get("displayName", service_principal)
            break

    return (
        f"Service Principal Credentials Added: [{actor}] added credentials "
        f"to service principal [{service_principal}]"
    )


def alert_context(event):
    # Build context for audit logs (not sign-in logs)
    fields = {
        "tenantId": ("tenantId", "<NO_TENANTID>"),
        "operation_name": ("operationName", "<NO_OPERATION>"),
        "activity_display_name": ("properties", "activityDisplayName", "<NO_ACTIVITY>"),
        "category": ("category", "<NO_CATEGORY>"),
        "result": ("properties", "result", "<NO_RESULT>"),
        "actor_user": ("properties", "initiatedBy", "user", "userPrincipalName", "<NO_ACTOR>"),
        "initiator_user_id": ("properties", "initiatedBy", "user", "id", "<NO_USER_ID>"),
        "initiator_display_name": (
            "properties",
            "initiatedBy",
            "user",
            "displayName",
            "<NO_DISPLAY_NAME>",
        ),
        "source_ip": ("properties", "initiatedBy", "user", "ipAddress", "<NO_IP>"),
    }

    context = {}
    for key, field_path in fields.items():
        *path, default = field_path
        if len(path) > 1:
            context[key] = event.deep_get(*path, default=default)
        else:
            context[key] = event.get(path[0], default)

    # Add target service principal details
    target_resources = event.deep_get("properties", "targetResources", default=[])
    service_principals = []

    for resource in target_resources or []:
        if resource.get("type") in ["ServicePrincipal", "Application"]:
            sp_info = {
                "id": resource.get("id", ""),
                "displayName": resource.get("displayName", ""),
                "type": resource.get("type"),
            }

            # Extract credential details from modified properties
            credential_info = [
                {"property": prop.get("displayName"), "new_value": prop.get("newValue", "")}
                for prop in resource.get("modifiedProperties", [])
                if prop.get("displayName") in ["KeyDescription", "KeyType", "KeyUsage"]
            ]

            if credential_info:
                sp_info["credential_details"] = credential_info

            service_principals.append(sp_info)

    if service_principals:
        context["target_service_principals"] = service_principals

    return context
