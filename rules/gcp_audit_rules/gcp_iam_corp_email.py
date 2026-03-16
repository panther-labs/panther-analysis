from fnmatch import fnmatch

from panther_base_helpers import deep_get

# These patterns indicate members which might be added by default by some GCP services
ACCEPTED_MEMBER_PATTERNS = [
    "serviceAccount:*@*.gserviceaccount.com",
    "serviceAccount:*.svc.id.goog[*",
    "principalSet://iam.googleapis.com/projects/*/workloadIdentityPools/*",
]


def rule(event):
    if event.deep_get("protoPayload", "methodName") != "SetIamPolicy":
        return False

    service_data = event.deep_get("protoPayload", "serviceData")
    if not service_data:
        return False

    authenticated = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default=""
    )
    expected_domain = authenticated.split("@")[-1]

    binding_deltas = deep_get(service_data, "policyDelta", "bindingDeltas")
    if not binding_deltas:
        return False

    for delta in binding_deltas:
        if delta.get("action") != "ADD":
            continue
        member = delta.get("member", "")
        if any(fnmatch(member, pattern) for pattern in ACCEPTED_MEMBER_PATTERNS):
            continue  # Skip this member, check others
        if member.endswith(f"@{expected_domain}"):
            continue  # Skip this member, check others
        return True  # Found a suspicious member - alert
    return False  # No suspicious members found


def title(event):
    return (
        f"A GCP IAM account has been created with an unexpected email domain in "
        f"{event.deep_get('resource', 'labels', 'project_id', default='<UNKNOWN_PROJECT>')}"
    )
