BUCKET_OPERATIONS = ["storage.buckets.delete", "storage.buckets.update"]


def rule(event):
    return all(
        [
            event.deep_get("protoPayload", "serviceName", default="") == "storage.googleapis.com",
            event.deep_get("protoPayload", "methodName", default="") in BUCKET_OPERATIONS,
        ]
    )


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    operation = event.deep_get("protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
    project = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
    bucket = event.deep_get("resource", "labels", "bucket_name", default="<BUCKET_NOT_FOUND>")

    return f"GCP: [{actor}] performed a [{operation}] on bucket [{bucket}] in project [{project}]."
