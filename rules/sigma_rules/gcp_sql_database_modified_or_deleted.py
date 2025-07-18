def rule(event):
    if event.deep_get("protoPayload", "methodName", default="") in [
        "cloudsql.instances.create",
        "cloudsql.instances.delete",
        "cloudsql.users.update",
        "cloudsql.users.delete",
    ]:
        return True
    return False
