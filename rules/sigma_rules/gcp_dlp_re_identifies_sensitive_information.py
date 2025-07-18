def rule(event):
    if event.deep_get("protoPayload", "methodName", default="") == "projects.content.reidentify":
        return True
    return False
