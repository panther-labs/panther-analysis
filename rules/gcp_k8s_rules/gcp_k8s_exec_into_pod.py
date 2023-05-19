from gcp_base_helpers import get_k8s_info
from gcp_environment import PRODUCTION_PROJECT_IDS, rule_exceptions
from panther_base_helpers import deep_get


def rule(event):
    # Defaults to False (no alert) unless method is exec and principal not allowed
    if not deep_get(
        event, "protoPayload", "methodName"
    ) == "io.k8s.core.v1.pods.exec.create" or not deep_get(event, "protoPayload", "resourceName"):
        return False

    k8s_info = get_k8s_info(event)
    principal = k8s_info["principal"]
    namespace = k8s_info["namespace"]
    project_id = k8s_info["project_id"]
    # rule_exceptions that are allowed temporarily are defined in gcp_environment.py
    # Some execs have principal which is long numerical UUID, appears to be k8s internals
    for allowed_principal in rule_exceptions["gcp_k8s_exec_into_pod"]["allowed_principals"]:
        if (
            principal in allowed_principal["principals"]
            and (
                not allowed_principal["namespaces"] or namespace in allowed_principal["namespaces"]
            )
            and (not allowed_principal["projects"] or project_id in allowed_principal["projects"])
        ):
            # nested if since without we get linting error R0916
            if principal.find("@") == -1:
                return False
    return True


def severity(event):
    project_id = get_k8s_info(event)["project_id"]
    if project_id in PRODUCTION_PROJECT_IDS:
        return "high"
    return "info"


def title(event):
    # TODO: use unified data model field in title for actor
    k8s_info = get_k8s_info(event)
    principal = k8s_info["principal"]
    project_id = k8s_info["project_id"]
    pod = k8s_info["pod"]
    namespace = k8s_info["namespace"]
    return f"Exec into pod namespace/{namespace}/pod/{pod} by {principal} in {project_id}"


def alert_context(event):
    return get_k8s_info(event)
