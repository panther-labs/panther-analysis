from panther_gcp_helpers import gcp_alert_context


def rule(event):
    method_name = event.deep_get("protoPayload", "methodName", default="")
    return method_name.endswith("TagBindings.CreateTagBinding")


def title(event):
    principal = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN>"
    )
    resource = event.deep_get("protoPayload", "resourceName", default="<UNKNOWN>")
    return f"GCP Tag Binding Creation by {principal} - {resource}"


def alert_context(event):
    return gcp_alert_context(event)
