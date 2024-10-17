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
