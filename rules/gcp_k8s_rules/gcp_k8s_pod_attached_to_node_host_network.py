from panther_gcp_helpers import gcp_alert_context


def rule(event):
    if event.deep_get("protoPayload", "methodName") not in (
        "io.k8s.core.v1.pods.create",
        "io.k8s.core.v1.pods.update",
        "io.k8s.core.v1.pods.patch",
    ):
        return False

    host_network = event.deep_walk("protoPayload", "request", "spec", "hostNetwork")
    if host_network is not True:
        return False

    return True


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return (
        f"[GCP]: [{actor}] created or modified pod which is attached to the host's network "
        f"in project [{project_id}]"
    )


def dedup(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return actor


def alert_context(event):
    return gcp_alert_context(event)
