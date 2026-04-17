def rule(event):
    return all(
        [
            event.deep_get("resource", "type", default="") == "service_account",
            "CreateServiceAccount" in event.deep_get("protoPayload", "methodName", default=""),
            not event.deep_get(
                "protoPayload", "authenticationInfo", "principalEmail", default=""
            ).endswith(".gserviceaccount.com"),
        ]
    )


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    target = event.deep_get("resource", "labels", "email_id")
    project = event.deep_get("resource", "labels", "project_id")
    resource = (
        "Service Account Key for"
        if event.deep_get("protoPayload", "methodName", default="")
        == "google.iam.admin.v1.CreateServiceAccountKey"
        else "Service Account"
    )
    return f"GCP: [{actor}] created {resource} [{target}] in project [{project}]"
