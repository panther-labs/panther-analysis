import json
from unittest.mock import MagicMock

from panther_base_helpers import deep_walk
from panther_gcp_helpers import get_k8s_info

# This is a list of principals that are allowed to exec into pods
# in various namespaces and projects.
ALLOW_LIST = [
    {
        # If empty, then no principals
        "principals": [
            # "system:serviceaccount:example-namespace:example-namespace-service-account",
        ],
        # If empty, then all namespaces
        "namespaces": [],
        # If projects empty then all projects
        "projects": [],
    },
    # Add more allowed principals here
    # {
    #     "principals": [],
    #     "namespaces": [],
    #     "projects": [],
    # },
]


def rule(event):
    # pylint: disable=not-callable
    # pylint: disable=global-statement
    global ALLOW_LIST
    if isinstance(ALLOW_LIST, MagicMock):
        ALLOW_LIST = json.loads(ALLOW_LIST())

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
    for allowed_principal in ALLOW_LIST:
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
