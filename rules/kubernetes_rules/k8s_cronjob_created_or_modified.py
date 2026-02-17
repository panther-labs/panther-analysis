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
    response_status = event.udm("responseStatus")
    namespace = event.udm("namespace")
    username = event.udm("username")

    # Check for CronJob create/update/patch operations
    if verb in ("create", "update", "patch") and resource == "cronjobs":
        # Only alert on successful operations
        if is_failed_request(response_status):
            return False

        # Exclude status updates (routine execution tracking, not spec changes)
        if subresource == "status":
            return False

        # Exclude system controllers creating/modifying CronJobs in system namespaces
        if is_system_namespace(namespace) and is_system_principal(username):
            return False

        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    cronjob_name = event.udm("name") or "<UNKNOWN>"
    verb = event.udm("verb")

    action = "created" if verb == "create" else "modified"
    return f"[{username}] {action} CronJob " f"[{namespace}/{cronjob_name}]"


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    namespace = event.udm("namespace") or "<UNKNOWN_NAMESPACE>"
    return f"k8s_cronjob_{username}_{namespace}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={
            "cronjob_name": event.udm("name"),
            "requestObject": event.udm("requestObject"),
        },
    )
