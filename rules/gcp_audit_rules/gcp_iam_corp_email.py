from panther_base_helpers import deep_get

EXPECTED_DOMAIN = "@your-domain.tld"


def rule(event):
    if event.deep_get("protoPayload", "methodName") != "SetIamPolicy":
        return False

    service_data = event.deep_get("protoPayload", "serviceData")
    if not service_data:
        return False

    # Reference: bit.ly/2WsJdZS
    binding_deltas = deep_get(service_data, "policyDelta", "bindingDeltas")
    if not binding_deltas:
        return False

    for delta in binding_deltas:
        if delta.get("action") != "ADD":
            continue
        if delta.get("member", "").endswith(EXPECTED_DOMAIN):
            return False
    return True


def title(event):
    return (
        f"A GCP IAM account has been created with an unexpected email domain in "
        f"{event.deep_get('resource', 'labels', 'project_id', default='<UNKNOWN_PROJECT>')}"
    )
