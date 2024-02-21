from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get, deep_walk


SUSPICIOUS_PATHS = [
    "/var/run/docker.sock",
    "/var/run/crio/crio.sock",
    "/var/lib/kubelet",
    "/var/lib/kubelet/pki",
    "/var/lib/docker/overlay2",
    "/etc/kubernetes",
    "/etc/kubernetes/manifests",
    "/etc/kubernetes/pki",
    "/home/admin",
]


def rule(event):
    if deep_get(event, "protoPayload", "response", "status") == "Failure":
        return False

    if deep_get(event, "protoPayload", "methodName") not in (
        "io.k8s.core.v1.pods.create",
        "io.k8s.core.v1.pods.update",
        "io.k8s.core.v1.pods.patch",
    ):
        return False

    volume_mount_path = deep_walk(
        event, "protoPayload", "request", "spec", "volumes", "hostPath", "path"
    )
    if volume_mount_path not in SUSPICIOUS_PATHS and not any(
        path in SUSPICIOUS_PATHS for path in volume_mount_path
    ):
        return False

    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    for auth in authorization_info:
        if (
            auth.get("permission")
            in (
                "io.k8s.core.v1.pods.create",
                "io.k8s.core.v1.pods.update",
                "io.k8s.core.v1.pods.patch",
            )
            and auth.get("granted") is True
        ):
            return True
    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    pod_name = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return (
        f"[GCP]: [{actor}] created k8s pod [{pod_name}] with a hostPath volume mount "
        f"in project [{project_id}]"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    volume_mount_path = deep_walk(
        event, "protoPayload", "request", "spec", "volumes", "hostPath", "path"
    )
    context["volume_mount_path"] = volume_mount_path
    return context
