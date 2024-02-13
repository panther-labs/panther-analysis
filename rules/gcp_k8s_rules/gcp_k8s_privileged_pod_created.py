from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_get, deep_walk


def rule(event):
    if deep_get(event, "protoPayload", "response", "status") == "Failure":
        return False

    if deep_get(event, "protoPayload", "methodName") != "io.k8s.core.v1.pods.create":
        return False

    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    containers_info = deep_walk(event, "protoPayload", "response", "spec", "containers")
    for auth in authorization_info:
        if auth.get("permission") == "io.k8s.core.v1.pods.create" and auth.get("granted") is True:
            for security_context in containers_info:
                if (
                    deep_get(security_context, "securityContext", "privileged") is True
                    or deep_get(security_context, "securityContext", "runAsNonRoot") is False
                ):
                    return True

    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    pod_name = deep_get(event, "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] created a privileged pod [{pod_name}] in project [{project_id}]"


def alert_context(event):
    context = gcp_alert_context(event)
    containers_info = deep_walk(event, "protoPayload", "response", "spec", "containers")
    context["pod_security_context"] = [i.get("securityContext") for i in containers_info]
    return context
