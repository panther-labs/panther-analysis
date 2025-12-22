from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

ROLEBINDING_OPERATIONS = [
    # Arc-enabled Kubernetes clusters
    "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE",
    "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE",
    # AKS managed clusters
    "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE",
    (
        "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/"
        "CLUSTERROLEBINDINGS/WRITE"
    ),
]


def rule(event):
    return event.get(
        "operationName", ""
    ).upper() in ROLEBINDING_OPERATIONS and azure_activity_success(event)


def title(event):
    operation = event.get("operationName", "").upper()
    binding_type = "ClusterRoleBinding" if "CLUSTERROLEBINDINGS" in operation else "RoleBinding"

    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    cluster_name = "<UNKNOWN_CLUSTER>"

    if resource_id:
        parts = resource_id.split("/")
        if "connectedClusters" in parts:
            try:
                cluster_name = parts[parts.index("connectedClusters") + 1]
            except (IndexError, ValueError):
                pass
        elif "managedClusters" in parts:
            try:
                cluster_name = parts[parts.index("managedClusters") + 1]
            except (IndexError, ValueError):
                pass

    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")
    title_str = f"Azure Kubernetes {binding_type} Created in [{cluster_name}] by [{caller}]"
    return title_str


def alert_context(event):
    context = azure_activity_alert_context(event)

    operation = event.get("operationName", "").upper()
    context["binding_type"] = (
        "ClusterRoleBinding" if "CLUSTERROLEBINDINGS" in operation else "RoleBinding"
    )

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")
        if "connectedClusters" in parts:
            try:
                context["cluster_name"] = parts[parts.index("connectedClusters") + 1]
                context["cluster_type"] = "Arc-enabled"
            except (IndexError, ValueError):
                pass
        elif "managedClusters" in parts:
            try:
                context["cluster_name"] = parts[parts.index("managedClusters") + 1]
                context["cluster_type"] = "AKS Managed"
            except (IndexError, ValueError):
                pass

    return context
