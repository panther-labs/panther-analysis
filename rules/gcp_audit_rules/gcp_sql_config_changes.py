from panther_base_helpers import deep_get


def rule(event):
    return deep_get(event, "protoPayload", "methodName") == "cloudsql.instances.update"


def dedup(event):
    return deep_get(event, "resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
