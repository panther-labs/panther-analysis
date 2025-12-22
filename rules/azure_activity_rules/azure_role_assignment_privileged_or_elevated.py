from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    azure_parse_requestbody,
)

ROLE_ASSIGNMENT_WRITE = "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"

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


def _get_role_def_id(request_body):
    if not request_body:
        return None

    properties = request_body.get("Properties") or request_body.get("properties")
    if not properties:
        return None

    return properties.get("RoleDefinitionId") or properties.get("roleDefinitionId")


def _match_role_name(role_def_id):
    # Match role definition ID to a privileged or elevated role name
    if not role_def_id:
        return None

    # Role definition IDs format:
    # /subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{id}
    role_def_id_lower = str(role_def_id).lower()

    # Check privileged roles first
    for priv_role_id, priv_role_name in PRIVILEGED_ROLES.items():
        if priv_role_id.lower() in role_def_id_lower:
            return priv_role_name

    # Check elevated roles
    for elevated_role_id, elevated_role_name in ELEVATED_ROLES.items():
        if elevated_role_id.lower() in role_def_id_lower:
            return elevated_role_name

    return None


def extract_role_name(event):
    # Extract and return the role name being assigned from the event
    request_body = azure_parse_requestbody(event)
    role_def_id = _get_role_def_id(request_body)
    return _match_role_name(role_def_id)


def rule(event):
    if event.get("operationName", "").upper() != ROLE_ASSIGNMENT_WRITE:
        return False

    # Check if a privileged or elevated role is being assigned
    return extract_role_name(event) is not None and azure_activity_success(event)


def title(event):
    role_assignment = event.deep_get("resourceId", default="<UNKNOWN_ASSIGNMENT>")
    caller = event.deep_get("callerIpAddress", default="<UNKNOWN_CALLER>")
    role_name = extract_role_name(event) or "<UNKNOWN_ROLE>"
    role_str = "<UNKNOWN_ROLE_TYPE>"
    if role_name in PRIVILEGED_ROLES.values():
        role_str = "privileged"
    if role_name in ELEVATED_ROLES.values():
        role_str = "elevated"
    return (
        f"Azure [{role_str}] role "
        f"[{role_name}] assigned on "
        f"[{role_assignment}] by [{caller}]"
    )


def severity(event):
    # Get the role name being assigned
    role_name = extract_role_name(event)

    if role_name:
        # Check if it's a privileged role (MEDIUM severity)
        if role_name in PRIVILEGED_ROLES.values():
            return "HIGH"
        # Check if it's an elevated role (LOW severity)
        if role_name in ELEVATED_ROLES.values():
            return "MEDIUM"

    return "DEFAULT"


def _add_request_body_fields(context, request_body):
    if not request_body:
        return

    properties = request_body.get("Properties") or request_body.get("properties")
    if not properties:
        return

    role_def_id = properties.get("RoleDefinitionId") or properties.get("roleDefinitionId")
    principal_id = properties.get("PrincipalId") or properties.get("principalId")
    principal_type = properties.get("PrincipalType") or properties.get("principalType")

    if role_def_id:
        context["role_definition_id"] = role_def_id
    if principal_id:
        context["principal_id"] = principal_id
    if principal_type:
        context["principal_type"] = principal_type


def alert_context(event):
    context = azure_activity_alert_context(event)

    # Parse and add request body fields
    request_body = azure_parse_requestbody(event)
    _add_request_body_fields(context, request_body)

    # Add role name
    role_name = extract_role_name(event)
    if role_name:
        context["role_name"] = role_name

    return context
