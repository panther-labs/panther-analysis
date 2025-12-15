def rule(event):

    if (
        event.deep_get("protoPayload", "serviceName") != "storage.googleapis.com"
        or event.deep_get("protoPayload", "methodName") != "storage.buckets.update"
        or event.get("severity") == "ERROR"  # Operation failed
    ):
        return False

    return True


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="Unknown"
    )
    bucket = event.deep_get("resource", "labels", "bucket_name", default="Unknown")
    return f"GCS bucket [{bucket}] configuration updated by [{actor}]"


def alert_context(event):
    return {
        "actor": event.deep_get("protoPayload", "authenticationInfo", "principalEmail"),
        "bucket": event.deep_get("resource", "labels", "bucket_name"),
        "source_ip": event.deep_get("protoPayload", "requestMetadata", "callerIp"),
        "user_agent": event.deep_get("protoPayload", "requestMetadata", "callerSuppliedUserAgent"),
        "project": event.deep_get("resource", "labels", "project_id"),
    }
