def rule(event):
    if event.deep_get("protoPayload", "methodName", default="") in [
        "storage.buckets.delete",
        "storage.buckets.insert",
        "storage.buckets.update",
        "storage.buckets.patch",
    ]:
        return True
    return False
