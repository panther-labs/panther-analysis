def rule(event):
    return (
        event.deep_get("resource", "type") == "gcs_bucket"
        and event.deep_get("protoPayload", "methodName") == "storage.setIamPermissions"
    )


def dedup(event):
    return event.deep_get("resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
