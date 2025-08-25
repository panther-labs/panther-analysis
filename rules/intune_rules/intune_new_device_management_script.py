from panther_base_helpers import deep_get


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

    # Retern a generic title if the operation is unknown
    if OPERATION == "Unknown":
        return f"A change to InTune device management scripts was performed by [{ACTOR}]."

    # The script type is the second word in the operation
    script_type = OPERATION.split(" ")[1]
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
        "Object IDs": deep_get(event, "properties", "TargetObjectIds", default="Unknown"),
    }
