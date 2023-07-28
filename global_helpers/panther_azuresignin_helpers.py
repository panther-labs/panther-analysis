from panther_base_helpers import deep_get


def actor_user(event):
    category = deep_get(event, "category", default="")
    if category in {"ServicePrincipalSignInLogs"}:
        return deep_get(event, "properties", "servicePrincipalName")
    if category in {"SignInLogs", "NonInteractiveUserSignInLogs"}:
        return deep_get(event, "properties", "userPrincipalName")
    return None


def azure_signin_alert_context(event) -> dict:
    ac_actor_user = actor_user(event)
    if ac_actor_user is None:
        ac_actor_user = "<NO_ACTORUSER>"
    a_c = {}
    a_c["tenantId"] = deep_get(event, "tenantId", default="<NO_TENANTID>")
    a_c["source_ip"] = deep_get(event, "properties", "ipAddress", default="<NO_SOURCEIP>")
    a_c["actor_user"] = ac_actor_user
    a_c["resourceDisplayName"] = deep_get(
        event, "properties", "resourceDisplayName", default="<NO_RESOURCEDISPLAYNAME>"
    )
    a_c["resourceId"] = deep_get(event, "properties", "resourceId", default="<NO_RESOURCEID>")
    return a_c
