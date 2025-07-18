def rule(event):
    if event.deep_get("protoPayload", "methodName", default="") in [
        "storage.buckets.list",
        "storage.buckets.listChannels",
    ]:
        return True
    return False
