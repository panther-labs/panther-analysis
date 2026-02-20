from panther_kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    username = event.udm("username")
    response_status = event.udm("responseStatus")

    # Only check CertificateSigningRequest creation
    if verb != "create" or resource != "certificatesigningrequests":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals
    if is_system_principal(username):
        return False

    # Exclude node bootstrap processes that legitimately create CSRs during cluster operations
    if username == "kubelet-nodepool-bootstrap":
        return False

    # Check if this is for client authentication
    request_object = event.udm("requestObject") or {}
    spec = request_object.get("spec", {})
    usages = spec.get("usages", [])
    signer_name = spec.get("signerName", "")

    # Look for client auth certificates
    if "client auth" in usages or "kubernetes.io/kube-apiserver-client" in signer_name:
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    name = event.udm("name") or "<UNKNOWN_CSR>"

    return f"[{username}] created client certificate signing request [{name}]"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    name = event.udm("name") or "<UNKNOWN_CSR>"
    return f"k8s_client_cert_{username}_{name}"


def alert_context(event):
    request_object = event.udm("requestObject") or {}
    spec = request_object.get("spec", {})

    return k8s_alert_context(
        event,
        extra_fields={
            "csr_name": event.udm("name"),
            "signer_name": spec.get("signerName"),
            "usages": spec.get("usages"),
            "groups": spec.get("groups"),
        },
    )
