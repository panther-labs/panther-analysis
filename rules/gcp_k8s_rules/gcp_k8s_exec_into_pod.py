from panther_base_helpers import deep_walk
from panther_config_defaults import GCP_PRODUCTION_PROJECT_IDS, gcp_rule_exceptions
from panther_gcp_helpers import get_k8s_info


def rule(event):
    # Defaults to False (no alert) unless method is exec and principal not allowed
    if not all(
        [
            event.deep_walk("protoPayload", "methodName") == "io.k8s.core.v1.pods.exec.create",
            event.deep_walk("resource", "type") == "k8s_cluster",
        ]
    ):
        return False

    k8s_info = get_k8s_info(event)
    principal = deep_walk(k8s_info, "principal", default="<NO PRINCIPAL>")
    namespace = deep_walk(k8s_info, "namespace", default="<NO NAMESPACE>")
    project_id = deep_walk(k8s_info, "project_id", default="<NO PROJECT_ID>")
    # rule_exceptions that are allowed temporarily are defined in gcp_environment.py
    # Some execs have principal which is long numerical UUID, appears to be k8s internals
    for allowed_principal in deep_walk(
        gcp_rule_exceptions, "gcp_k8s_exec_into_pod", "allowed_principals", default=[]
    ):
        allowed_principals = deep_walk(allowed_principal, "principals", default=[])
        allowed_namespaces = deep_walk(allowed_principal, "namespaces", default=[])
        allowed_project_ids = deep_walk(allowed_principal, "projects", default=[])
        if (
            principal in allowed_principals
            and (namespace in allowed_namespaces or allowed_namespaces == [])
            and (project_id in allowed_project_ids or allowed_project_ids == [])
        ):
            if "@" not in principal:
                return False
    return True


def severity(event):
    project_id = deep_walk(get_k8s_info(event), "project_id", default="<NO PROJECT_ID>")
    if project_id in GCP_PRODUCTION_PROJECT_IDS:
        return "high"
    return "info"


def title(event):
    # TODO: use unified data model field in title for actor
    k8s_info = get_k8s_info(event)
    principal = deep_walk(k8s_info, "principal", default="<NO PRINCIPAL>")
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
