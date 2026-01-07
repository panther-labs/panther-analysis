import json


def azure_activity_alert_context(event) -> dict:
    a_c = {}
    a_c["resource_id"] = event.get("resourceId", "<UNKNOWN_RESOURCE_ID>")
    a_c["caller_ip"] = event.get("callerIpAddress", "<UNKNOWN_CALLER_IP>")
    a_c["operation_name"] = event.get("operationName", "<UNKNOWN_OPERATION_NAME>")
    a_c["result_type"] = event.get("resultType", "<UNKNOWN_RESULT_TYPE>")
    a_c["correlation_id"] = event.get("correlationId", "<UNKNOWN_CORRELATION_ID>")
    a_c["location"] = event.get("location", "<UNKNOWN_LOCATION>")
    a_c["tenant_id"] = event.get("tenantId", "<UNKNOWN_TENANT_ID>")

    resource_id = event.get("resourceId", "")
    storage_account_name = extract_resource_name_from_id(resource_id, "storageAccounts", default="")
    if storage_account_name:
        a_c["storage_account_name"] = storage_account_name

    resource_group = extract_resource_name_from_id(resource_id, "resourceGroups", default="")
    if resource_group:
        a_c["resource_group"] = resource_group

    properties = event.get("properties", "")
    if properties:
        a_c["properties"] = properties
    return a_c


def azure_activity_success(event):
    result = event.get("resultType", "")
    if result in ["Success", "Succeeded"]:
        return True
    return False


def azure_resource_logs_success(event):
    response_type = event.deep_get("properties", "metricResponseType", default="")
    if response_type == "Success":
        return True
    return False


def azure_resource_logs_failure(event):
    response_type = event.deep_get("properties", "metricResponseType", default="")
    if response_type != "Success":
        return True
    return False


def azure_parse_json_string(json_str):
    """Parse field which can be a JSON string or object.

    Azure Monitor Activity logs store a few fields as a JSON string, but test logs
    may have it as an object for readability. This function handles both cases.

    Returns:
        dict: Parsed field as a dictionary, or empty dict if parsing fails
    """
    if json_str is None:
        return {}

    # If already a dict, return it
    if isinstance(json_str, dict):
        return json_str

    # If string, try to parse as JSON
    if isinstance(json_str, str):
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return {}

    return {}


def extract_resource_name_from_id(resource_id, resource_type, default="<UNKNOWN>"):
    """Extract resource name from Azure resourceId path.

    Azure resourceId paths follow the format:
    /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{resourceType}/{name}/...

    Args:
        resource_id: Full Azure resource ID path
        resource_type: Type to extract (e.g., 'storageAccounts', 'vaults', 'runbooks')
        default: Default value if extraction fails (can be None or str)

    Returns:
        Extracted resource name or default value

    """
    if not resource_id:
        return default

    parts = resource_id.split("/")
    if resource_type in parts:
        try:
            idx = parts.index(resource_type)
            if idx + 1 < len(parts):
                return parts[idx + 1]
        except (ValueError, IndexError):
            pass

    return default


def get_role_definition_id(request_body):
    """Extract role definition ID from Azure role assignment request body.

    Handles case-insensitive property names (Properties vs properties,
    RoleDefinitionId vs roleDefinitionId) that may appear in Azure Activity logs.

    Args:
        request_body: Parsed request body dictionary

    Returns:
        Role definition ID string or None if not found
    """
    if not request_body:
        return None

    properties = request_body.get("Properties") or request_body.get("properties")
    if not properties:
        return None

    return properties.get("RoleDefinitionId") or properties.get("roleDefinitionId")


def match_role_name(role_def_id, role_mappings):
    """Match Azure role definition ID to a role name.

    Role definition IDs follow the format:
    /subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{id}

    Args:
        role_def_id: Full role definition ID path
        role_mappings: Dictionary mapping role IDs to role names

    Returns:
        Role name if found in mappings, None otherwise
    """
    if not role_def_id:
        return None

    role_def_id_lower = str(role_def_id).lower()

    for role_id, role_name in role_mappings.items():
        if role_id.lower() in role_def_id_lower:
            return role_name

    return None


def add_role_assignment_fields(context, request_body):
    """Extract and add role assignment fields to alert context.

    Handles case-insensitive property names that may appear in Azure Activity logs.

    Args:
        context: Alert context dictionary to update
        request_body: Parsed request body dictionary
    """
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
