def rule(event):

    method_name = event.deep_get("protoPayload", "methodName", default="UNKNOWN_METHOD_NAME")
    service_name = event.deep_get("protoPayload", "serviceName")
    severity = event.get("severity")
    return all(
        [
            method_name == "storage.objects.delete",
            service_name == "storage.googleapis.com",
            severity != "ERROR",  # Operation succeeded
        ]
    )


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
