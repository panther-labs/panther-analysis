from panther_base_helpers import deep_get


def rule(event):
    return all(
        [
            deep_get(event, "resource", "type", default="") == "service_account",
            "CreateServiceAccount" in deep_get(event, "protoPayload", "methodName", default=""),
            not deep_get(
                event, "protoPayload", "authenticationInfo", "principalEmail", default=""
            ).endswith(".gserviceaccount.com"),
        ]
    )


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    target = deep_get(event, "resource", "labels", "email_id")
    project = deep_get(event, "resource", "labels", "project_id")
    resource = (
        "Service Account Key for"
        if deep_get(event, "protoPayload", "methodName", default="")
        == "google.iam.admin.v1.CreateServiceAccountKey"
        else "Service Account"
    )
    return f"GCP: [{actor}] created {resource} [{target}] in project [{project}]"
