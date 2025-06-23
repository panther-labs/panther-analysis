from panther_gcp_helpers import gcp_alert_context

PRIVILEGED_OPERATIONS = [
        "iam.serviceAccounts.getAccessToken",
        "orgpolicy.policy.set",
        "storage.hmacKeys.create",
        "serviceusage.apiKeys.create",
        "serviceusage.apiKeys.list",
    ]


def rule(event):
    method_name = event.deep_get("protoPayload", "methodName", default="")
    return method_name.endswith("setIamPolicy") or method_name in PRIVILEGED_OPERATIONS


def title(event):
    principal = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN>"
    )
    method = event.deep_get("protoPayload", "methodName", default="<UNKNOWN>")
    return f"GCP Privileged Operation by {principal} - {method}"


def alert_context(event):
    return gcp_alert_context(event)
