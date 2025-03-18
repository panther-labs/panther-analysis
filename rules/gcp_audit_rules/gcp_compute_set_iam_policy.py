from panther_gcp_helpers import gcp_alert_context, get_binding_deltas

SUSPICIOUS_ACTIONS = [
    "v1.compute.disks.setIamPolicy",
    "v1.compute.images.setIamPolicy",
    "v1.compute.snapshots.setIamPolicy",
]


def rule(event):
    if event.deep_get("protoPayload", "response", "error"):
        return False

    method = event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND")
    if method in SUSPICIOUS_ACTIONS:
        return True

    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )

    items = event.deep_get("protoPayload", "methodName", default="ITEMS_NOT_FOUND. ").split(".")[-2]

    project = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
    return f"[GCP]: [{actor}] updated IAM policy for [{items}] on project [{project}]"


def alert_context(event):
    context = gcp_alert_context(event)
    service_accounts = event.deep_get("protoPayload", "request", "serviceAccounts")
    if not service_accounts:
        service_account_emails = "<SERVICE_ACCOUNT_EMAILS_NOT_FOUND>"
    else:
        service_account_emails = [service_acc["email"] for service_acc in service_accounts]
    context["serviceAccount"] = service_account_emails
    context["binding_deltas"] = get_binding_deltas(event)
    return context
