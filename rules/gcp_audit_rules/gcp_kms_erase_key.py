def rule(event):
    if event.deep_get("protoPayload", "serviceName") != "cloudkms.googleapis.com":
        return False

    method = event.deep_get("protoPayload", "methodName", default="<UNKNOWN_METHOD>")

    # Direct key version destruction
    if method == "DestroyCryptoKeyVersion":
        return True

    # Key version state change, check for dangerous states
    if method == "UpdateCryptoKeyVersion":
        if event.deep_get("protoPayload", "request", "updateMask") != "state":
            return False

        crypto_key_state = event.deep_get(
            "protoPayload", "request", "cryptoKeyVersion", "state", default="<UNKNOWN_STATE>"
        )
        dangerous_states = ["DISABLED", "DESTROY_SCHEDULED", "DESTROYED"]
        return crypto_key_state in dangerous_states

    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="Unknown"
    )
    key = event.deep_get("protoPayload", "request", "cryptoKeyVersion", "name", default="Unknown")
    return f"GCP KMS key [{key}] version disabled or destroyed by {actor}"


def alert_context(event):
    return {
        "actor": event.deep_get("protoPayload", "authenticationInfo", "principalEmail"),
        "kms_key_version": event.deep_get("protoPayload", "resourceName"),
        "new_state": event.deep_get("protoPayload", "request", "cryptoKeyVersion", "state"),
        "source_ip": event.deep_get("protoPayload", "requestMetadata", "callerIp"),
        "project": event.deep_get("resource", "labels", "project_id"),
        "key_ring": event.deep_get("resource", "labels", "key_ring_id"),
        "crypto_key": event.deep_get("resource", "labels", "crypto_key_id"),
    }
