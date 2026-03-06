from panther_base_helpers import deep_get
from panther_kubernetes_helpers import (
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    namespace = event.udm("namespace")
    username = event.udm("username")
    response_status = event.udm("responseStatus")

    # Only check ingress creation events
    if verb != "create" or resource != "ingresses":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system namespaces and system principals to reduce false positives
    if is_system_namespace(namespace) or is_system_principal(username):
        return False

    # Check if ingress has TLS configuration
    tls = deep_get(event.udm("requestObject"), "spec", "tls")

    # Alert if TLS is not configured (missing or empty)
    if not tls:
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_INGRESS>"

    return f"[{username}] created Ingress [{namespace}/{name}] without TLS certificate"


def dedup(event):
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_INGRESS>"
    return f"k8s_ingress_no_tls_{namespace}_{name}"


def severity(event):
    """Increase severity based on ingress annotations and rules."""
    request_object = event.udm("requestObject") or {}
    metadata = request_object.get("metadata", {})
    annotations = metadata.get("annotations", {})

    # Check if this is an external-facing ingress (has external annotations)
    external_annotations = [
        "kubernetes.io/ingress.class",
        "cert-manager.io/cluster-issuer",
        "external-dns.alpha.kubernetes.io/hostname",
    ]

    if any(key in annotations for key in external_annotations):
        return "MEDIUM"

    return "DEFAULT"


def alert_context(event):
    request_object = event.udm("requestObject") or {}
    spec = request_object.get("spec", {})
    rules = spec.get("rules", [])
    metadata = request_object.get("metadata", {})
    annotations = metadata.get("annotations", {})

    # Extract hosts from ingress rules
    hosts = []
    for rule_entry in rules:
        host = rule_entry.get("host")
        if host:
            hosts.append(host)

    return k8s_alert_context(
        event,
        extra_fields={
            "ingress_name": event.udm("name"),
            "ingress_hosts": hosts,
            "annotations": annotations,
            "has_tls": False,
        },
    )
