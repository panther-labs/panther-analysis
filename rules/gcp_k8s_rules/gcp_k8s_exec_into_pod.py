from gcp_base_helpers import get_k8s_info
from gcp_environment import PRODUCTION_PROJECT_IDS, rule_exceptions
from panther_base_helpers import deep_walk


def rule(event):
    # Defaults to False (no alert) unless method is exec and principal not allowed
    if not deep_walk(
        event, "protoPayload", "methodName"
    ) == "io.k8s.core.v1.pods.exec.create" or not deep_walk(event, "protoPayload", "resourceName"):
        return False

    k8s_info = get_k8s_info(event)
    principal = deep_walk(k8s_info, "principal", default="")
    namespace = deep_walk(k8s_info, "namespace", default="")
    project_id = deep_walk(k8s_info, "project_id", default="")
    # rule_exceptions that are allowed temporarily are defined in gcp_environment.py
    # Some execs have principal which is long numerical UUID, appears to be k8s internals
    for allowed_principal in deep_walk(
        rule_exceptions, "gcp_k8s_exec_into_pod", "allowed_principals", default=""
    ):
        if (
            principal in deep_walk(allowed_principal, "principals", default="")
            and (
                not deep_walk(allowed_principal, "namespaces", default="")
                or namespace in deep_walk(allowed_principal, "namespaces", default="")
            )
            and (
                not deep_walk(allowed_principal, "projects", default="")
                or project_id in deep_walk(allowed_principal, "projects", default="")
            )
        ):
            if principal.find("@") == -1:
                return False
    return True


def severity(event):
    project_id = deep_walk(get_k8s_info(event), "project_id", default="")
    if project_id in PRODUCTION_PROJECT_IDS:
        return "high"
    return "info"


def title(event):
    # TODO: use unified data model field in title for actor
    k8s_info = get_k8s_info(event)
    principal = deep_walk(k8s_info, "principal", default="")
    project_id = deep_walk(
        k8s_info,
        "project_id",
        default="",
    )
    pod = deep_walk(k8s_info, "pod", default="")
    namespace = deep_walk(k8s_info, "namespace", default="")
    return f"Exec into pod namespace/{namespace}/pod/{pod} by {principal} in {project_id}"


def alert_context(event):
    return get_k8s_info(event)
