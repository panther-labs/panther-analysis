def rule(event):

    if (
        event.deep_get("protoPayload", "methodName") != "Encrypt"
        or event.deep_get("protoPayload", "serviceName") != "cloudkms.googleapis.com"
        or "gs-project-accounts.iam.gserviceaccount.com"
        not in event.deep_get(
            "protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN_PRINCIPAL>"
        )
        or event.get("severity") == "ERROR"  # Operation failed
    ):
        return False

    return True


def title(event):
    key = event.deep_get("resource", "labels", "crypto_key_id", default="Unknown")
    return f"GCS service account performing bulk KMS encryption with key [{key}]"


def alert_context(event):
    return {
        "principal": event.deep_get("protoPayload", "authenticationInfo", "principalEmail"),
        "kms_key": event.deep_get("protoPayload", "resourceName"),
        "key_ring": event.deep_get("resource", "labels", "key_ring_id"),
        "crypto_key": event.deep_get("resource", "labels", "crypto_key_id"),
        "project": event.deep_get("resource", "labels", "project_id"),
        "status": event.deep_get("protoPayload", "status"),
        "location": event.deep_get("resource", "labels", "location"),
    }
