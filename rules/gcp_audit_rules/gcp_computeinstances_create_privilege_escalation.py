from panther_gcp_helpers import gcp_alert_context

REQUIRED_PERMISSIONS = [
    "compute.disks.create",
    "compute.instances.create",
    "compute.instances.setMetadata",
    "compute.instances.setServiceAccount",
    "compute.subnetworks.use",
    "compute.subnetworks.useExternalIp",
]


def rule(event):
    if event.deep_get("protoPayload", "response", "error"):
        return False

    method = event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND")
    if not method.endswith("compute.instances.insert"):
        return False

    # Skip allowlisted actors
    principal = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="")
    if principal.endswith("@cloudservices.gserviceaccount.com"):
        return False

    granted_permissions = {}
    for auth in event.deep_walk("protoPayload", "authorizationInfo") or []:
        granted_permissions[auth.get("permission")] = auth.get("granted")
    for permission in REQUIRED_PERMISSIONS:
        if not granted_permissions.get(permission):
            return False

    return True


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )

    service_accounts = event.deep_get("protoPayload", "request", "serviceAccounts")
    if not service_accounts:
        service_account_emails = "<SERVICE_ACCOUNT_EMAILS_NOT_FOUND>"
    else:
        service_account_emails = [service_acc["email"] for service_acc in service_accounts]

    project = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
    return (
        f"[GCP]: [{actor}] created a new Compute Engine instance with [{service_account_emails}] "
        f"Service Account on project [{project}]"
    )


def alert_context(event):
    context = gcp_alert_context(event)
    service_accounts = event.deep_get("protoPayload", "request", "serviceAccounts")
    if not service_accounts:
        service_account_emails = "<SERVICE_ACCOUNT_EMAILS_NOT_FOUND>"
    else:
        service_account_emails = [service_acc["email"] for service_acc in service_accounts]
    context["serviceAccount"] = service_account_emails
    return context
