def rule(event):

    method_name = event.deep_get("protoPayload", "methodName")
    service_name = event.deep_get("protoPayload", "serviceName")
    principal = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN_PRINCIPAL>"
    )
    severity = event.get("severity")
    return all(
        [
            method_name == "Encrypt",
            service_name == "cloudkms.googleapis.com",
            "gs-project-accounts.iam.gserviceaccount.com" in principal,
            severity != "ERROR",  # Operation succeeded
        ]
    )


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
