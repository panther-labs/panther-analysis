from gcp_base_helpers import gcp_alert_context

METHODS_TO_CHECK = [
    "io.k8s.core.v1.pods.create",
    "io.k8s.core.v1.pods.update",
    "io.k8s.core.v1.pods.patch",
]


def rule(event):
    method = event.deep_get("protoPayload", "methodName")
    request_host_pid = event.deep_get("protoPayload", "request", "spec", "hostPID")
    response_host_pid = event.deep_get("protoPayload", "responce", "spec", "hostPID")
    if (request_host_pid is True or response_host_pid is True) and method in METHODS_TO_CHECK:
        return True
    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return (
        f"[GCP]: [{actor}] created or modified pod using the host PID namespace "
        f"in project [{project_id}]"
    )


def alert_context(event):
    return gcp_alert_context(event)
