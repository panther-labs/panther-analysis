from base64 import b64decode

from panther_base_helpers import deep_get


def rule(event):
    # Alert on creation or modification of mobile apps
    return event.get("operationName").lower() in ["create mobileapp", "patch mobileapp"]


def title(event):
    # Simple title with the native Defender alert title
    user = event.get("identity", default="Unknown")

    if event.get("operationName").lower().startswith("create"):
        return f"An InTune mobile app was created by [{user}]"

    return f"An InTune mobile app was modified by [{user}]"


def alert_context(event):

    context = {
        "Actor": event.get("identity", default="Unknown"),
        "Operation": event.get("operationName", default="Unknown"),
        "Deployed App(s)": deep_get(event, "properties", "TargetDisplayNames", default="Unknown"),
    }

    # Intune allows administrators to write PowerShell scripts to verify an app is properly
    # installed. These scripts can be used for malicious purposes. If a new script is added,
    # it will be in a ModifiedProperty section for hte given app, and will be base64 encoded
    scripts = []
    targets = deep_get(event, "properties", "Targets")
    for target in targets:
        for prop in target["ModifiedProperties"]:
            if "Collection.Rules.ScriptContent" in prop.get("Name") and prop.get("New"):
                scripts.append(b64decode(prop.get("New")).decode("utf8"))
    if scripts:
        context["Validation Script(s)"] = scripts

    return context
