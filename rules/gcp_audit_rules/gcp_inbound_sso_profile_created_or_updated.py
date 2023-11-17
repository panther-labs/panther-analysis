METHODS = [
    "google.admin.AdminService.inboundSsoProfileCreated",
    "google.admin.AdminService.inboundSsoProfileUpdated",
]


def rule(event):
    return event.deep_walk("protoPayload", "methodName", default="") in METHODS


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    event_name = event.deep_walk(
        "protoPayload", "metadata", "event", "eventName", default="<EVENT_NAME_NOT_FOUND>"
    )

    resource = organization_id = event.deep_walk(
        "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
    ).split("/")

    organization_id = resource[resource.index("organizations") + 1]

    return f"GCP: [{actor}] performed {event_name} in organization {organization_id}"


def alert_context(event):
    return {
        "resourceName": event.deep_get(
            "protoPayload", "resourceName", default="<RESOURCE_NOT_FOUND>"
        ),
        "serviceName": event.deep_get("protoPayload", "serviceName", default="<SERVICE_NOT_FOUND>"),
    }
