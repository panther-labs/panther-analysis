from panther_gcp_helpers import gcp_alert_context, is_gke_system_namespace, is_gke_system_principal

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
    # Check basic conditions
    if event.deep_get("protoPayload", "response", "status") == "Failure" or event.deep_get(
        "protoPayload", "methodName"
    ) not in (
        "io.k8s.core.v1.pods.create",
        "io.k8s.core.v1.pods.update",
        "io.k8s.core.v1.pods.patch",
    ):
        return False

    # Check if volume mount path is suspicious
    volume_mount_path = event.deep_walk(
        "protoPayload", "request", "spec", "volumes", "hostPath", "path"
    )

    has_suspicious_path = volume_mount_path and (
        volume_mount_path in SUSPICIOUS_PATHS
        or any(path in SUSPICIOUS_PATHS for path in volume_mount_path)
    )

    if not has_suspicious_path:
        return False

    # Check if this is a known GKE system service account or system namespace
    principal_email = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default=""
    )
    resource_name = event.deep_get("protoPayload", "resourceName", default="")

    if is_gke_system_principal(principal_email) or is_gke_system_namespace(resource_name):
        return False

    # Check authorization
    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

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
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    pod_name = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return (
        f"[GCP]: [{actor}] created k8s pod [{pod_name}] with a hostPath volume mount "
        f"in project [{project_id}]"
    )


def dedup(event):
    return event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    volume_mount_path = event.deep_walk(
        "protoPayload", "request", "spec", "volumes", "hostPath", "path"
    )
    context["volume_mount_path"] = volume_mount_path
    return context
