from panther_okta_helpers import okta_alert_context

DANGEROUS_SCOPES = [
    "okta.users.manage",
    "okta.factors.manage",
    "okta.apps.manage",
    "okta.groups.manage",
    "okta.policies.manage",
]
HIGH_RISK_SCOPES = {"okta.users.manage", "okta.factors.manage"}
SERVICE_APP_ACTOR_TYPE = "PublicClientAppEntity"


def _tokenize(granted_scopes):
    return {s.strip() for s in granted_scopes.split(",")}


def _target_includes_user(event):
    for entry in event.get("target") or []:
        if isinstance(entry, dict) and entry.get("type") == "User":
            return True
    return False


def rule(event):
    if event.get("eventType") != "app.oauth2.token.grant.access_token":
        return False
    if event.deep_get("outcome", "result") != "SUCCESS":
        return False
    # The rule's intended signal is a service app acquiring a token via client_credentials —
    # a flow with no user subject. Gate on actor.type and reject grants that name a User target
    # so user-driven token flows that happen to share fields don't trigger this detection.
    if event.deep_get("actor", "type", default="") != SERVICE_APP_ACTOR_TYPE:
        return False
    if _target_includes_user(event):
        return False
    grant_type = event.deep_get("debugContext", "debugData", "grantType") or ""
    if grant_type != "client_credentials":
        return False
    granted_scopes = event.deep_get("debugContext", "debugData", "grantedScopes") or ""
    scopes = _tokenize(granted_scopes)
    return any(scope in scopes for scope in DANGEROUS_SCOPES)


def title(event):
    app_name = event.deep_get("actor", "displayName") or "Unknown App"
    app_id = event.deep_get("actor", "alternateId") or event.deep_get("actor", "id") or "unknown"
    scopes = event.deep_get("debugContext", "debugData", "grantedScopes") or "unknown scopes"
    source_ip = event.deep_get("client", "ipAddress") or "unknown IP"
    return (
        f"Okta service app dangerous-scope token grant: "
        f"{app_name} ({app_id}) acquired [{scopes}] from {source_ip}"
    )


def severity(event):
    granted_scopes = event.deep_get("debugContext", "debugData", "grantedScopes") or ""
    if HIGH_RISK_SCOPES & _tokenize(granted_scopes):
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return okta_alert_context(event)
