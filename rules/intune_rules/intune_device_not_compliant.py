ACTOR = OPERATION = ""


def rule(event):
    # pylint: disable=global-statement
    global OPERATION

    # Alert on DeviceManagementScript or DeviceHealthScript events
    OPERATION = event.get("operationName", "")
    return ("DeviceManagementScript" in OPERATION) or ("DeviceComplianceScript" in OPERATION)


def title(event):
    # pylint: disable=global-statement
    global ACTOR

    # Simple title with the native Defender alert title
    ACTOR = event.get("identity", "")

    # The script type is the second word in the operation
    script_type_parts = OPERATION.split(" ")
    if len(script_type_parts) > 1:
        script_type = script_type_parts[1]
    else:
        script_type = "Unknown"

    if OPERATION.startswith("create"):
        action = "created"
    elif OPERATION.startswith("assign"):
        action = "assigned"
    elif OPERATION.startswith("delete"):
        action = "deleted"
    elif OPERATION.startswith("patched"):
        action = "patched"
    else:
        action = "modified"

    return f"INTUNE: [{ACTOR}] [{action}] an InTune [{script_type}] script"


def alert_context(event):
    return {
        "Hostname": event.deep_get("properties", "DeviceHostName", default="Unknown"),
        "Operating System": event.deep_get(
            "properties", "DeviceOperatingSystem", default="Unknown"
        ),
        "User": ACTOR,
        "Description": event.deep_get("properties", "Description", default="Unknown"),
    }
