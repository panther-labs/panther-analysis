from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get, deep_walk


def rule(event):
    if deep_get(event, "protoPayload", "methodName") not in (
        "io.k8s.core.v1.pods.create",
        "io.k8s.core.v1.pods.update",
        "io.k8s.core.v1.pods.patch",
    ):
        return False

    host_network = deep_walk(event, "protoPayload", "request", "spec", "hostNetwork")
    if host_network is not True:
        return False

    return True


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    pod_name = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return (
        f"[GCP]: [{actor}] created or modified pod which is attached to the host's network "
        f"in project [{project_id}]"
    )


def alert_context(event):
    return gcp_alert_context(event)
