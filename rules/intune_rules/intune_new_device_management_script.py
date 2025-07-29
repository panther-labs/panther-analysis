from panther_base_helpers import deep_get


def rule(event):
    # Alert on DeviceManagementScript or DeviceHealthScript events
    operation = event.get("operationName")
    return ("DeviceManagementScript" in operation) or ("DeviceComplianceScript" in operation)


def title(event):
    # Simple title with the native Defender alert title
    user = event.get("identity", default="Unknown")

    # The operation contains the action and the type of script
    operation = event.get("operationName", default="Unknown")

    # Retern a generic title if the operation is unknown
    if operation == "Unknown":
        return f"A change to InTune device management scripts was performed by [{user}]."

    # The script type is the second word in the operation
    script_type = operation.split(" ")[1]
    if operation.startswith("create"):
        action = "created"
    elif operation.startswith("assign"):
        action = "assigned"
    elif operation.startswith("delete"):
        action = "deleted"
    elif operation.startswith("patched"):
        action = "patched"
    else:
        action = "unknown"

    return f"An InTune device [{script_type}] script was [{action}] by [{user}]"


def alert_context(event):
    return {
        "Actor": event.get("identity", default="Unknown"),
        "Operation": event.get("operationName", default="Unknown"),
        "Object IDs": deep_get(event, "properties", "TargetObjectIds", default="Unknown"),
    }
