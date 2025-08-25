from panther_base_helpers import deep_get


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

    # The operation contains the action and the type of script
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
        action = "modified"

    return f"INTUNE: [{ACTOR}] [{action}] an InTune [{script_type}] script"


def alert_context(event):
    return {
        "Hostname": deep_get(event, "properties", "DeviceHostName", default="Unknown"),
        "Operating System": deep_get(
            event, "properties", "DeviceOperatingSystem", default="Unknown"
        ),
        "User": ACTOR,
        "Description": deep_get(event, "properties", "Description", default="Unknown"),
    }
