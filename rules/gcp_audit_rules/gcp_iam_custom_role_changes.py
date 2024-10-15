ROLE_METHODS = {
    "google.iam.admin.v1.CreateRole",
    "google.iam.admin.v1.DeleteRole",
    "google.iam.admin.v1.UpdateRole",
}


def rule(event):
    return (
        event.deep_get("resource", "type") == "iam_role"
        and event.deep_get("protoPayload", "methodName") in ROLE_METHODS
    )


def dedup(event):
    return event.deep_get("resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
