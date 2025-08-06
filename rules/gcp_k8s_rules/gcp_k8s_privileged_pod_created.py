from panther_base_helpers import deep_get
from panther_gcp_helpers import gcp_alert_context, is_gke_system_namespace, is_gke_system_principal


def rule(event):
    # Check basic conditions that would exclude this event
    if (
        event.deep_get("protoPayload", "response", "status") == "Failure"
        or event.deep_get("protoPayload", "methodName") != "io.k8s.core.v1.pods.create"
    ):
        return False

    # Check if this is a known service account or system namespace that should be excluded
    principal_email = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default=""
    )
    resource_name = event.deep_get("protoPayload", "resourceName", default="")

    if is_gke_system_principal(principal_email) or is_gke_system_namespace(resource_name):
        return False

    # Check for privileged pod creation
    authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    containers_info = event.deep_walk("protoPayload", "response", "spec", "containers")
    for auth in authorization_info:
        if auth.get("permission") == "io.k8s.core.v1.pods.create" and auth.get("granted") is True:
            for security_context in containers_info:
                # Check for privileged pods and pods running as root
                # Reference:
                # https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
                if (
                    deep_get(security_context, "securityContext", "privileged") is True
                    or deep_get(security_context, "securityContext", "runAsNonRoot") is False
                ):
                    return True

    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    pod_name = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] created a privileged pod [{pod_name}] in project [{project_id}]"


def dedup(event):
    return event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    containers_info = event.deep_walk("protoPayload", "response", "spec", "containers", default=[])
    context["pod_security_context"] = [i.get("securityContext") for i in containers_info]
    return context
