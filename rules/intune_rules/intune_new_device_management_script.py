ACTOR = OPERATION = ""


def rule(event):
    # pylint: disable=global-statement
    global OPERATION

    # Alert on DeviceManagementScript or DeviceHealthScript events
    OPERATION = event.get("operationName")
    return ("DeviceManagementScript" in OPERATION) or ("DeviceComplianceScript" in OPERATION)


def title(event):
    # pylint: disable=global-statement
    global ACTOR

    ACTOR = event.get("identity", "")

    # Return a generic title if the operation is unknown
    if OPERATION == "Unknown":
        return f"A change to InTune device management scripts was performed by [{ACTOR}]."

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
        action = "unknown"

    return f"An InTune device [{script_type}] script was [{action}] by [{ACTOR}]"


def alert_context(event):
    return {
        "Actor": ACTOR,
        "Operation": OPERATION,
        "Object IDs": event.deep_get("properties", "TargetObjectIds", default="Unknown"),
    }
