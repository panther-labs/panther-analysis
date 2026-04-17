def rule(event):
    return event.deep_get("protoPayload", "methodName") == "cloudsql.instances.update"


def dedup(event):
    return event.deep_get("resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
