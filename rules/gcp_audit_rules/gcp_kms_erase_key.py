def rule(event):

    if (
        event.deep_get("protoPayload", "methodName") != "UpdateCryptoKeyVersion"
        or event.deep_get("protoPayload", "serviceName") != "cloudkms.googleapis.com"
        or event.deep_get("protoPayload", "request", "updateMask") != "state"
    ):
        return False

    # Check if the key is being disabled or destroyed
    crypto_key_state = event.deep_get(
        "protoPayload", "request", "cryptoKeyVersion", "state", default="<UNKNOWN_STATE>"
    )
    dangerous_states = ["DISABLED", "DESTROY_SCHEDULED", "DESTROYED"]

    return crypto_key_state in dangerous_states


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="Unknown"
    )
    state = event.deep_get(
        "protoPayload", "request", "cryptoKeyVersion", "state", default="Unknown"
    )
    key = event.deep_get("protoPayload", "request", "cryptoKeyVersion", "name", default="Unknown")
    return f"GCP KMS key [{key}] version set to {state} by {actor}"


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
