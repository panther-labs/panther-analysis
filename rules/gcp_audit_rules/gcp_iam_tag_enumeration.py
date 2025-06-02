from panther_gcp_helpers import gcp_alert_context

def rule(event):
    enum_iam_tags = [
        "GetIamPolicy",
        "TagKeys.ListTagKeys",
        "TagKeys.ListTagValues",
        "TagBindings.ListEffectiveTags"
    ]
    
    method_name = event.deep_get("protoPayload", "methodName", default="")
    return method_name in enum_iam_tags

def title(event):
    return f"GCP IAM and Tag Enumeration by {event.deep_get('protoPayload', 'authenticationInfo', 'principalEmail', default='<UNKNOWN>')} - {event.deep_get('protoPayload', 'methodName', default='<UNKNOWN>')}"

def alert_context(event):
    return gcp_alert_context(event) 