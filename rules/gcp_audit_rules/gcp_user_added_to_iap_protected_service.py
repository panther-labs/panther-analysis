def rule(event):
    return (
        event.deep_get("protoPayload", "methodName", default="")
        == "google.cloud.iap.v1.IdentityAwareProxyAdminService.SetIamPolicy"
    )


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    service = event.deep_get("protoPayload", "request", "resource", default="<RESOURCE_NOT_FOUND>")
    return f"GCP: [{actor}] modified user access to IAP Protected Service [{service}]"


def alert_context(event):
    bindings = event.deep_get("protoPayload", "request", "policy", "bindings", default=[{}])

    return {"bindings": bindings}
