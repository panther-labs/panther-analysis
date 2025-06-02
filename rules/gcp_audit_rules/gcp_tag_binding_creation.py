from panther_gcp_helpers import gcp_alert_context

def rule(event):
    method_name = event.deep_get("protoPayload", "methodName", default="")
    return method_name == "TagBindings.CreateTagBinding"

def title(event):
    return f"GCP Tag Binding Creation by {event.deep_get('protoPayload', 'authenticationInfo', 'principalEmail', default='<UNKNOWN>')} - {event.deep_get('protoPayload', 'resourceName', default='<UNKNOWN>')}"

def alert_context(event):
    return gcp_alert_context(event) 