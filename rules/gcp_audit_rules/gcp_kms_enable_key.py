def rule(event):
    method_name = event.deep_get("protoPayload", "methodName")
    service_name = event.deep_get("protoPayload", "serviceName")
    status_code = event.deep_get("protoPayload", "status", "code")

    # Pre-filter
    # return False if any basic condition fails
    if any(
        [
            method_name != "SetIamPolicy",
            service_name != "cloudkms.googleapis.com",
            status_code,  # Operation failed
        ]
    ):
        return False

    # Extract the policy bindings from the request
    bindings = event.deep_get("protoPayload", "request", "policy", "bindings", default=[])

    for binding in bindings:
        role = binding.get("role", "")
        members = binding.get("members", [])

        # Check if granting KMS encryption/decryption permissions
        role_lower = role.lower()
        if "cryptokey" in role_lower and ("encrypt" in role_lower or "decrypt" in role_lower):
            for member in members:
                # Alert if granting to GCS service account
                if "gs-project-accounts.iam.gserviceaccount.com" in member:
                    return True

    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="Unknown"
    )
    kms_key = event.deep_get("protoPayload", "resourceName", default="Unknown")
    return f"GCP KMS key [{kms_key}] granted encryption permissions by [{actor}]"


def alert_context(event):
    bindings = event.deep_get("protoPayload", "request", "policy", "bindings", default=[])
    return {
        "actor": event.deep_get("protoPayload", "authenticationInfo", "principalEmail"),
        "kms_key": event.deep_get("protoPayload", "resourceName"),
        "source_ip": event.deep_get("protoPayload", "requestMetadata", "callerIp"),
        "project": event.deep_get("resource", "labels", "project_id"),
        "bindings": bindings,
    }
