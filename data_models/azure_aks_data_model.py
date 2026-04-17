"""Azure AKS Audit Data Model for parsing Kubernetes audit logs from Azure Monitor Activity"""

import json

from panther_base_helpers import deep_get


def _is_aks_audit_log(event):
    """Check if this is an AKS kube-audit log"""
    category = event.get("category", "")
    return category in ("kube-audit", "kube-audit-admin")


def _parse_k8s_audit_log(event):
    """Parse the Kubernetes audit log from properties.log field"""
    if not _is_aks_audit_log(event):
        return None

    log_string = deep_get(event, "properties", "log", default="")
    if not log_string:
        return None

    try:
        return json.loads(log_string)
    except (json.JSONDecodeError, TypeError):
        return None


def get_annotations(event):
    """Extract annotations from Kubernetes audit log"""
    k8s_log = _parse_k8s_audit_log(event)
    return k8s_log.get("annotations") if k8s_log else None


def get_api_group(event):
    """Extract API group from objectRef"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "objectRef", "apiGroup") if k8s_log else None


def get_api_version(event):
    """Extract API version from objectRef"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "objectRef", "apiVersion") if k8s_log else None


def get_namespace(event):
    """Extract namespace from objectRef"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "objectRef", "namespace") if k8s_log else None


def get_resource(event):
    """Extract resource type from objectRef"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "objectRef", "resource") if k8s_log else None


def get_name(event):
    """Extract resource name from objectRef"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "objectRef", "name") if k8s_log else None


def get_subresource(event):
    """Extract subresource from objectRef"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "objectRef", "subresource") if k8s_log else None


def get_request_uri(event):
    """Extract request URI"""
    k8s_log = _parse_k8s_audit_log(event)
    return k8s_log.get("requestURI") if k8s_log else None


def get_response_status(event):
    """Extract response status"""
    k8s_log = _parse_k8s_audit_log(event)
    return k8s_log.get("responseStatus") if k8s_log else None


def get_source_ips(event):
    """Extract source IPs"""
    k8s_log = _parse_k8s_audit_log(event)
    return k8s_log.get("sourceIPs") if k8s_log else None


def get_username(event):
    """Extract username from user object"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "user", "username") if k8s_log else None


def get_user_agent(event):
    """Extract user agent"""
    k8s_log = _parse_k8s_audit_log(event)
    return k8s_log.get("userAgent") if k8s_log else None


def get_verb(event):
    """Extract Kubernetes API verb (get, list, create, update, delete, etc.)"""
    k8s_log = _parse_k8s_audit_log(event)
    return k8s_log.get("verb") if k8s_log else None


def get_request_object(event):
    """Extract request object"""
    k8s_log = _parse_k8s_audit_log(event)
    return k8s_log.get("requestObject") if k8s_log else None


def get_response_object(event):
    """Extract response object"""
    k8s_log = _parse_k8s_audit_log(event)
    return k8s_log.get("responseObject") if k8s_log else None


def get_containers(event):
    """Extract containers from requestObject.spec.containers"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "requestObject", "spec", "containers") if k8s_log else None


def get_volumes(event):
    """Extract volumes from requestObject.spec.volumes"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "requestObject", "spec", "volumes") if k8s_log else None


def get_host_ipc(event):
    """Extract hostIPC from requestObject.spec.hostIPC"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "requestObject", "spec", "hostIPC") if k8s_log else None


def get_host_network(event):
    """Extract hostNetwork from requestObject.spec.hostNetwork"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "requestObject", "spec", "hostNetwork") if k8s_log else None


def get_host_pid(event):
    """Extract hostPID from requestObject.spec.hostPID"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "requestObject", "spec", "hostPID") if k8s_log else None


def get_webhooks(event):
    """Extract webhooks from requestObject.webhooks"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "requestObject", "webhooks") if k8s_log else None


def get_service_type(event):
    """Extract service type from requestObject.spec.type"""
    k8s_log = _parse_k8s_audit_log(event)
    return deep_get(k8s_log, "requestObject", "spec", "type") if k8s_log else None
