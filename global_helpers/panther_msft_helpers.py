from panther_base_helpers import deep_get, deep_walk


def msft_graph_alert_context(event):
    return {
        "category": event.get("category", ""),
        "description": event.get("description", ""),
        "userStates": event.get("userStates", []),
        "fileStates": event.get("fileStates", []),
        "hostStates": event.get("hostStates", []),
    }


def m365_alert_context(event):
    return {
        "operation": event.get("Operation", ""),
        "organization_id": event.get("OrganizationId", ""),
        "client_ip": event.get("ClientIp", ""),
        "extended_properties": event.get("ExtendedProperties", []),
        "modified_properties": event.get("ModifiedProperties", []),
        "application": event.get("Application", ""),
        "actor": event.get("Actor", []),
    }


def azure_rule_context(event: dict):
    return {
        "operationName": event.get("operationName", default="<MISSING_OPERATION_NAME>"),
        "category": deep_get(event, "properties", "category", default="<MISSING_CATEGORY>"),
        "actor_id": deep_get(
            event, "properties", "initiatedBy", "user", "id", default="<MISSING_ACTOR_ID"
        ),
        "actor_upn": deep_get(
            event, "properties", "initiatedBy", "user", "userPrincipalName", default="<MISSING UPN>"
        ),
        "source_ip_address": deep_get(
            event, "properties", "initiatedBy", "user", "ipAddress", default="<MISSING_SOURCE_IP>"
        ),
        "target_id": deep_walk(
            event, "properties", "targetResources", "id", default="<MISSING_ACCOUNT_ID>"
        ),
        "target_name": deep_walk(
            event, "properties", "targetResources", "displayName", default="<MISSING UPN>"
        ),
    }


def get_target_name(event, target_type="User"):
    target_resources = deep_walk(event, "properties", "targetResources", default="")
    for resource in target_resources:
        if resource.get("type") == target_type:
            return resource.get("displayName", "NO DISPLAY NAME FOUND")

    return "NO DISPLAY NAME FOUND"


def azure_success(event):
    result = event.deep_get("properties", "result", default="")
    return result == "success"
