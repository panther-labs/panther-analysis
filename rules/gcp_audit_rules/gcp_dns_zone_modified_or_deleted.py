from panther_base_helpers import deep_get


def rule(event):
    methods = (
        "dns.changes.create",
        "dns.managedZones.delete",
        "dns.managedZones.patch",
        "dns.managedZones.update",
    )
    return deep_get(event, "protoPayload", "methodName", default="") in methods


def title(event):
    actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="")
    method = deep_get(event, "protoPayload", "methodName", default="")
    resource = deep_get(event, "protoPayload", "resourceName", default="")
    return f"{actor} performed {method} on {resource}"


def alert_context(event):
    metadata = {}
    for label, value in deep_get(event, "resource", "labels", default={}).items():
        metadata[label] = value
    metadata["type"] = deep_get(event, "resource", "type", default="")
    metadata["callerIP"] = deep_get(
        event, "protoPayload", "requestMetadata", "callerIP", default=""
    )
    return dict(sorted(metadata.items()))
