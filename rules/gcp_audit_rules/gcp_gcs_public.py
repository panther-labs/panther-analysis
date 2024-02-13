from panther_base_helpers import deep_get

GCS_READ_ROLES = {"roles/storage.objectAdmin", "roles/storage.objectViewer", "roles/storage.admin"}
GLOBAL_USERS = {"allUsers", "allAuthenticatedUsers"}


def rule(event):
    if deep_get(event, "protoPayload", "methodName") != "storage.setIamPermissions":
        return False

    service_data = deep_get(event, "protoPayload", "serviceData")
    if not service_data:
        return False

    # Reference: https://cloud.google.com/iam/docs/policies
    binding_deltas = deep_get(service_data, "policyDelta", "bindingDeltas")
    if not binding_deltas:
        return False

    for delta in binding_deltas:
        if delta.get("action") != "ADD":
            continue
        if delta.get("member") in GLOBAL_USERS and delta.get("role") in GCS_READ_ROLES:
            return True
    return False


def title(event):
    return (
        f"GCS bucket "
        f"[{deep_get(event, 'resource', 'labels', 'bucket_name', default='<UNKNOWN_BUCKET>')}] "
        f"made public"
    )
