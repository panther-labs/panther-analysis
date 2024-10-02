def actor_user(event):
    category = event.get("category", "")
    if category in {"ServicePrincipalSignInLogs"}:
        return event.deep_get("properties", "servicePrincipalName")
    if category in {"SignInLogs", "NonInteractiveUserSignInLogs"}:
        return event.deep_get("properties", "userPrincipalName")
    return None


def is_sign_in_event(event):
    return event.get("operationName", "") == "Sign-in activity"


def azure_signin_alert_context(event) -> dict:
    ac_actor_user = actor_user(event)
    if ac_actor_user is None:
        ac_actor_user = "<NO_ACTORUSER>"
    a_c = {}
    a_c["tenantId"] = event.get("tenantId", "<NO_TENANTID>")
    a_c["source_ip"] = event.deep_get("properties", "ipAddress", default="<NO_SOURCEIP>")
    a_c["actor_user"] = ac_actor_user
    a_c["resourceDisplayName"] = event.deep_get(
        "properties", "resourceDisplayName", default="<NO_RESOURCEDISPLAYNAME>"
    )
    a_c["resourceId"] = event.deep_get("properties", "resourceId", default="<NO_RESOURCEID>")
    return a_c
