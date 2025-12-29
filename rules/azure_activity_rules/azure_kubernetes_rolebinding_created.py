from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

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
    cluster_name = extract_resource_name_from_id(resource_id, "connectedClusters", default="")
    if not cluster_name:
        cluster_name = extract_resource_name_from_id(
            resource_id, "managedClusters", default="<UNKNOWN_CLUSTER>"
        )

    title_str = f"Azure Kubernetes {binding_type} Created in [{cluster_name}]"
    return title_str


def alert_context(event):
    context = azure_activity_alert_context(event)

    operation = event.get("operationName", "").upper()
    context["binding_type"] = (
        "cluster_role_binding" if "CLUSTERROLEBINDINGS" in operation else "role_binding"
    )

    resource_id = event.get("resourceId", "")

    cluster_name = extract_resource_name_from_id(resource_id, "connectedClusters", default="")
    if cluster_name:
        context["cluster_name"] = cluster_name
        context["cluster_type"] = "arc_enabled"
    else:
        cluster_name = extract_resource_name_from_id(resource_id, "managedClusters", default="")
        if cluster_name:
            context["cluster_name"] = cluster_name
            context["cluster_type"] = "aks_managed"

    return context
