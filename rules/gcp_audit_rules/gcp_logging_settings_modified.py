def rule(event):
    return all(
        [
            event.deep_get("protoPayload", "serviceName", default="") == "logging.googleapis.com",
            "Update" in event.deep_get("protoPayload", "methodName", default=""),
        ]
    )


def title(event):
    resource = event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>")
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return f"GCP [{resource}] logging settings modified by [{actor}]."


def dedup(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    return actor


def alert_context(event):
    return {
        "resource": event.deep_get("protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"),
        "actor": event.deep_get(
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        ),
        "method": event.deep_get("protoPayload", "methodName", default="<METHOD_NOT_FOUND>"),
    }
