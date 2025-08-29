from base64 import b64decode

ACTOR = OPERATION = ""


def rule(event):
    # pylint: disable=global-statement
    global OPERATION

    OPERATION = event.get("operationName", "")

    # Alert on creation or modification of mobile apps
    return OPERATION.lower() in ["create mobileapp", "patch mobileapp"]


def title(event):
    # pylint: disable=global-statement
    global ACTOR

    ACTOR = event.get("identity", "")

    if OPERATION.lower().startswith("create"):
        return f"Intune: [{ACTOR or '<N/A>'}] created a new Intune mobile app."

    return f"Intune: [{ACTOR or '<N/A>'}] modified an Intune mobile app"


def alert_context(event):

    context = {
        "Actor": event.get("identity", default="Unknown"),
        "Operation": event.get("operationName", default="Unknown"),
        "Deployed App(s)": event.deep_get("properties", "TargetDisplayNames", default="Unknown"),
    }

    # Intune allows administrators to write PowerShell scripts to verify an app is properly
    # installed. These scripts can be used for malicious purposes. If a new script is added,
    # it will be in a ModifiedProperty section for hte given app, and will be base64 encoded
    scripts = []
    targets = event.deep_get("properties", "Targets")
    for target in targets:
        for prop in target["ModifiedProperties"]:
            if "Collection.Rules.ScriptContent" in prop.get("Name") and prop.get("New"):
                scripts.append(b64decode(prop.get("New")).decode("utf8"))
    if scripts:
        context["Validation Script(s)"] = scripts

    return context
