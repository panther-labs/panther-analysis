def rule(event):

    if (
        event.deep_get("protoPayload", "methodName") != "storage.objects.delete"
        or event.deep_get("protoPayload", "serviceName") != "storage.googleapis.com"
        or event.get("severity") == "ERROR"  # Operation failed
    ):
        return False

    return True


def title(event):
    principal = event.deep_get("protoPayload", "authenticationInfo", "principalEmail")
    resource = event.deep_get("protoPayload", "resourceName")
    return f"GCP: Bulk object deletion in resource [{resource}] by principal [{principal}]"


def alert_context(event):
    return {
        "principal": event.deep_get("protoPayload", "authenticationInfo", "principalEmail"),
        "project": event.deep_get("resource", "labels", "project_id"),
        "status": event.deep_get("protoPayload", "status"),
        "location": event.deep_get("resource", "labels", "location"),
        "resource": event.deep_get("protoPayload", "resourceName"),
    }
