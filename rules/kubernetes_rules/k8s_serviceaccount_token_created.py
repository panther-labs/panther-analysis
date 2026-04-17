from panther_kubernetes_helpers import (
    is_failed_request,
    is_system_namespace,
    is_system_principal,
    k8s_alert_context,
)


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    subresource = event.udm("subresource")
    namespace = event.udm("namespace")
    username = event.udm("username")
    response_status = event.udm("responseStatus")

    # Only check serviceaccount token subresource creation
    if verb != "create" or resource != "serviceaccounts" or subresource != "token":
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude system principals in system namespaces (legitimate operations)
    # but alert on system principals in user namespaces (malicious controllers)
    # and alert on users creating tokens in system namespaces (privilege escalation)
    if is_system_principal(username) and is_system_namespace(namespace):
        return False

    return True


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_SA>"

    return f"[{username}] created long-lived token for service account " f"[{namespace}/{name}]"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    name = event.udm("name") or "<UNKNOWN_SA>"
    return f"k8s_token_created_{username}_{namespace}_{name}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "service_account": event.udm("name"),
            "namespace": event.udm("namespace"),
            "subresource": "token",
        },
    )
