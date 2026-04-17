from panther_azureactivity_helpers import (
    add_role_assignment_fields,
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_json_string,
    get_role_definition_id,
    match_role_name,
)

ROLE_ASSIGNMENT_WRITE = "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
ELEVATE_ACCESS_ACTION = "MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION"

# Common privileged role definition IDs (subscription-level built-in roles)
PRIVILEGED_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "fb1c8493-542b-48eb-b624-b4c8fea62acd": "Security Admin",
    "92b92042-07d9-4307-87f7-36a593fc5850": "Azure File Sync Administrator",
    "a8889054-8d42-49c9-bc1c-52486c10e7cd": "Reservations Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    "150f5e0c-0603-4f03-8c7f-cf70034c4e90": "Data Purger",
}

ELEVATED_ROLES = {
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner",
    "dffb1e0c-446f-4dde-a09f-99eb5cc68b96": "Azure Arc Kubernetes Admin",
    "a001fd3d-188f-4b5d-821b-7da978bf7442": "Cognitive Services OpenAI Contributor",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "8b54135c-b56d-4d72-a534-26097cfdc8d8": "Key Vault Data Access Administrator",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
}

# Combine all role mappings for lookup
ALL_ROLES = {**PRIVILEGED_ROLES, **ELEVATED_ROLES}


def extract_role_name(event):
    # Extract and return the role name being assigned from the event
    request_body = azure_parse_json_string(
        event.deep_get("properties", "requestbody", default=None)
    )
    role_def_id = get_role_definition_id(request_body)
    return match_role_name(role_def_id, ALL_ROLES)


def rule(event):
    # For elevate access, operationName is a dict with "value" key
    operation_name_value = event.deep_get("operationName", "value", default="")
    if operation_name_value:
        operation_name_value = str(operation_name_value).upper()
        # Check if this is the elevate access action (subscription-level elevation)
        if (
            operation_name_value == ELEVATE_ACCESS_ACTION
            and event.deep_get("status", "value") == "Succeeded"
        ):
            return True

    # For role assignments, operationName is a string
    operation_name = event.get("operationName", "")
    if isinstance(operation_name, str):
        operation_name = operation_name.upper()
        # Check if this is a privileged/elevated role assignment
        if operation_name == ROLE_ASSIGNMENT_WRITE:
            return extract_role_name(event) is not None and azure_activity_success(event)

    return False


def title(event):
    operation_name_value = event.deep_get(
        "operationName", "value", default="<UNKNOWN_OP_VALUE>"
    ).upper()

    # Handle elevate access action (subscription-level elevation)
    if operation_name_value == ELEVATE_ACCESS_ACTION:
        caller_identity = event.deep_get("identity", "claims", "name", default="<UNKNOWN_USER>")
        return f"Azure subscription access elevated by [{caller_identity}]"

    # Handle role assignment
    role_assignment = event.deep_get("resourceId", default="<UNKNOWN_ASSIGNMENT>")
    role_name = extract_role_name(event) or "<UNKNOWN_ROLE>"
    role_str = "<UNKNOWN_ROLE_TYPE>"
    if role_name in PRIVILEGED_ROLES.values():
        role_str = "privileged"
    if role_name in ELEVATED_ROLES.values():
        role_str = "elevated"
    return f"Azure [{role_str}] role " f"[{role_name}] assigned on " f"[{role_assignment}]"


def severity(event):
    operation_name_value = event.deep_get(
        "operationName", "value", default="<UNKNOWN_OP_VALUE>"
    ).upper()

    # Elevate access action grants User Access Administrator at root scope
    if operation_name_value == ELEVATE_ACCESS_ACTION:
        return "HIGH"

    # Get the role name being assigned
    role_name = extract_role_name(event)

    if role_name:
        # Check if it's a privileged role
        if role_name in PRIVILEGED_ROLES.values():
            return "HIGH"
        # Check if it's an elevated role
        if role_name in ELEVATED_ROLES.values():
            return "MEDIUM"

    return "DEFAULT"


def alert_context(event):
    context = azure_activity_alert_context(event)

    # Parse and add request body fields
    request_body = azure_parse_json_string(
        event.deep_get("properties", "requestbody", default=None)
    )
    add_role_assignment_fields(context, request_body)

    # Add role name
    role_name = extract_role_name(event)
    if role_name:
        context["role_name"] = role_name

    return context
