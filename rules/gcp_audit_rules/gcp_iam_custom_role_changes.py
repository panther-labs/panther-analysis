from panther_base_helpers import deep_get

ROLE_METHODS = {
    "google.iam.admin.v1.CreateRole",
    "google.iam.admin.v1.DeleteRole",
    "google.iam.admin.v1.UpdateRole",
}


def rule(event):
    return (
        deep_get(event, "resource", "type") == "iam_role"
        and deep_get(event, "protoPayload", "methodName") in ROLE_METHODS
    )


def dedup(event):
    return deep_get(event, "resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
