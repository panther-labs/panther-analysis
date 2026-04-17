from panther_gcp_helpers import gcp_alert_context


def rule(event):
    if (
        event.deep_get("protoPayload", "serviceName") != "cloudkms.googleapis.com"
        or event.deep_get("protoPayload", "methodName") != "Encrypt"
        or "gs-project-accounts.iam.gserviceaccount.com"
        not in event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="")
    ):
        return False

    # Get the target project from the log name
    # Format: projects/PROJECT/logs/cloudaudit.googleapis.com%2Fdata_access
    source_project = None
    if event.get("logName").startswith("projects/"):
        parts = event.get("logName").split("/")
        if len(parts) >= 2:
            source_project = parts[1]

    kms_project = None
    if event.deep_get("protoPayload", "resourceName").startswith("projects/"):
        parts = event.deep_get("protoPayload", "resourceName").split("/")
        if len(parts) >= 2:
            kms_project = parts[1]

    if source_project and kms_project is not None and source_project != kms_project:
        return True

    return False


def title(event):
    kms_key = event.deep_get("protoPayload", "resourceName", default="<UNKNOWN_KMS_KEY>")
    principal = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN_PRINCIPAL>"
    )
    return f"Cross-project KMS encryption by [{principal}] using key [{kms_key}] detected"


def alert_context(event):
    context = gcp_alert_context(event)
    context["kms_key"] = event.deep_get("protoPayload", "resourceName", default="<UNKNOWN_KMS_KEY>")
    return context
