METHODS = [
    "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
    "google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPoolProvider",
]


def rule(event):
    return event.deep_get("protoPayload", "methodName", default="") in METHODS


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>").split(
        "/"
    )
    workload_identity_pool = resource[resource.index("workloadIdentityPools") + 1]
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return (
        f"GCP: [{actor}] created or updated workforce pool "
        f"[{workload_identity_pool}] in project [{project_id}]"
    )


def alert_context(event):
    return event.deep_get("protoPayload", "request", "workloadIdentityPoolProvider", default={})
