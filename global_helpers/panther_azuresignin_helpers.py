from panther_base_helpers import deep_get


def actor_user(event):
    # 'event' could be a PantherEvent or an ImmutableCaseInsensitiveDict, so we have to use the
    #   imported deep_get method.
    category = event.get("category", "")
    if category in {"ServicePrincipalSignInLogs"}:
        return deep_get(event, "properties", "servicePrincipalName")
    if category in {"SignInLogs", "NonInteractiveUserSignInLogs"}:
        return deep_get(event, "properties", "userPrincipalName")
    return None


def is_sign_in_event(event):
    return event.get("operationName", "") == "Sign-in activity"


def azure_signin_alert_context(event) -> dict:
    actor_user_name = actor_user(event)
    if actor_user_name is None:
        actor_user_name = "<NO_ACTORUSER>"
    context = {}
    context["tenantId"] = event.get("tenantId", "<NO_TENANTID>")
    context["source_ip"] = event.deep_get("properties", "ipAddress", default="<NO_SOURCEIP>")
    context["actor_user"] = actor_user_name
    context["resourceDisplayName"] = event.deep_get(
        "properties", "resourceDisplayName", default="<NO_RESOURCEDISPLAYNAME>"
    )
    context["resourceId"] = event.deep_get("properties", "resourceId", default="<NO_RESOURCEID>")
    return context


def azure_signin_success(event):
    return event.get("resultSignature") == "SUCCESS"
