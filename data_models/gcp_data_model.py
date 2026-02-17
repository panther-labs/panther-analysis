import json
from fnmatch import fnmatch

import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get
from panther_gcp_helpers import get_binding_deltas

ADMIN_ROLES = {
    # Primitive Roles
    "roles/owner",
    # Predefined Roles
    "roles/*Admin",
}


def get_event_type(event):
    # currently, only tracking a handful of event types
    for delta in get_binding_deltas(event):
        if delta["action"] == "ADD":
            if any(
                (
                    fnmatch(delta.get("role", ""), admin_role_pattern)
                    for admin_role_pattern in ADMIN_ROLES
                )
            ):
                return event_type.ADMIN_ROLE_ASSIGNED

    return None


def get_admin_map(event):
    roles_assigned = {}
    for delta in get_binding_deltas(event):
        if delta.get("action") == "ADD":
            roles_assigned[delta.get("member")] = delta.get("role")

    return roles_assigned


def get_modified_users(event):
    event_dict = event.to_dict()
    roles_assigned = get_admin_map(event_dict)

    return json.dumps(list(roles_assigned.keys()))


def get_iam_roles(event):
    event_dict = event.to_dict()
    roles_assigned = get_admin_map(event_dict)

    return json.dumps(list(roles_assigned.values()))


def get_api_group(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        return resource_name.split("/", maxsplit=1)[0]
    except IndexError:
        return ""


def get_api_version(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        return resource_name.split("/")[1]
    except IndexError:
        return ""


def get_namespace(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        parts = resource_name.split("/")
        # Only namespaced resources have a namespace (contains "namespaces" in path)
        # e.g., core/v1/namespaces/default/pods/my-pod
        if len(parts) >= 4 and parts[2] == "namespaces":
            return parts[3]
        return ""
    except IndexError:
        return ""


def get_resource(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        parts = resource_name.split("/")
        # Cluster-scoped resources (e.g., mutatingwebhookconfigurations) at index 2
        # Namespaced resources (e.g., pods) at index 4
        if len(parts) >= 5:
            return parts[4]
        if len(parts) >= 3:
            return parts[2]
        return ""
    except IndexError:
        return ""


def get_name(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        parts = resource_name.split("/")
        # Namespaced resources have name at index 5 (e.g., core/v1/namespaces/default/pods/my-pod)
        # Cluster-scoped resources have name at index 3
        # (e.g., rbac.authorization.k8s.io/v1/clusterroles/admin)
        if len(parts) >= 6:
            return parts[5]
        if len(parts) >= 4:
            return parts[3]
        return ""
    except IndexError:
        return ""


def get_subresource(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
        return resource_name.split("/")[6]
    except IndexError:
        return ""


def get_request_uri(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    resource_name = str(deep_get(event, "protoPayload", "resourceName", default=""))
    return "/apis/" + resource_name


def get_source_ips(event):
    caller_ip = deep_get(event, "protoPayload", "requestMetadata", "callerIP", default=None)
    if caller_ip:
        return [caller_ip]
    return []


def get_verb(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    method_name = str(deep_get(event, "protoPayload", "methodName", default=""))
    return method_name.rsplit(".", maxsplit=1)[-1]


def get_actor_user(event):
    authentication_info = deep_get(event, "protoPayload", "authenticationInfo", default={})

    # For authenticated users (including impersonation), use principalEmail/Subject
    # Only use authoritySelector when there's no authenticated user (real anonymous access)
    if principal_email := authentication_info.get("principalEmail"):  # type: ignore[union-attr]
        return principal_email
    if principal_subject := authentication_info.get("principalSubject"):  # type: ignore[union-attr]
        return principal_subject

    # For real anonymous access (no authentication), GCP uses authoritySelector
    if authority := authentication_info.get("authoritySelector"):  # type: ignore[union-attr]
        return authority

    return "<UNKNOWN ACTOR USER>"


def get_containers(event):
    """Extract containers from protoPayload.request.spec.containers"""
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return None
    return deep_get(event, "protoPayload", "request", "spec", "containers")


def get_volumes(event):
    """Extract volumes from protoPayload.request.spec.volumes"""
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return None
    return deep_get(event, "protoPayload", "request", "spec", "volumes")


def get_host_ipc(event):
    """Extract hostIPC from protoPayload.request.spec.hostIPC"""
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return None
    return deep_get(event, "protoPayload", "request", "spec", "hostIPC")


def get_host_network(event):
    """Extract hostNetwork from protoPayload.request.spec.hostNetwork"""
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return None
    return deep_get(event, "protoPayload", "request", "spec", "hostNetwork")


def get_host_pid(event):
    """Extract hostPID from protoPayload.request.spec.hostPID"""
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return None
    return deep_get(event, "protoPayload", "request", "spec", "hostPID")


def get_webhooks(event):
    """Extract webhooks from protoPayload.request.webhooks"""
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return None
    return deep_get(event, "protoPayload", "request", "webhooks")


def get_service_type(event):
    """Extract service type from protoPayload.request.spec.type"""
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return None
    return deep_get(event, "protoPayload", "request", "spec", "type")
