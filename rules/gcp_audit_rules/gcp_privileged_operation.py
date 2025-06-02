from panther_gcp_helpers import gcp_alert_context

def rule(event):
    non_iam_privileged_operations = [
        "orgpolicy.policy.set",
        "storage.hmacKeys.create",
        "serviceusage.apiKeys.create",
        "serviceusage.apiKeys.list"
    ]
    
    method_name = event.deep_get("protoPayload", "methodName", default="")
    return method_name.endswith("setIamPolicy") or method_name in non_iam_privileged_operations

def title(event):
    return f"GCP Privileged Operation by {event.deep_get('protoPayload', 'authenticationInfo', 'principalEmail', default='<UNKNOWN>')} - {event.deep_get('protoPayload', 'methodName', default='<UNKNOWN>')}"

def alert_context(event):
    return gcp_alert_context(event) 