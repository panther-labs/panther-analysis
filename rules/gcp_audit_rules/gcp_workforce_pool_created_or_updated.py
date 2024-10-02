METHODS = [
    "google.iam.admin.v1.WorkforcePools.CreateWorkforcePool",
    "google.iam.admin.v1.WorkforcePools.UpdateWorkforcePool",
]


def rule(event):
    return event.deep_get("protoPayload", "methodName", default="") in METHODS


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    workforce_pool = event.deep_get(
        "protoPayload", "request", "workforcePool", "name", default=""
    ).split("/")[-1]

    resource = organization_id = event.get("logName", "<LOG_NAME_NOT_FOUND>").split(
        "/"
    )

    organization_id = resource[resource.index("organizations") + 1]

    return (
        f"GCP: [{actor}] created or updated workforce pool "
        f"[{workforce_pool}] in organization [{organization_id}]"
    )


def alert_context(event):
    return event.deep_get("protoPayload", "request", "workforcePool", default={})
