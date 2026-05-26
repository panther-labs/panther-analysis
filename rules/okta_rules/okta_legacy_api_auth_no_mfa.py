from panther_okta_helpers import okta_alert_context


LEGACY_SESSION_PREFIX = "102"
AUTOMATION_KEYWORDS = ["python", "curl", "requests", "powershell", "urllib", "okta-sdk"]


def rule(event):
    if event.get("eventType") != "user.session.start":
        return False
    if event.deep_get("outcome", "result") != "SUCCESS":
        return False
    session_id = event.deep_get("authenticationContext", "externalSessionId") or ""
    return session_id.startswith(LEGACY_SESSION_PREFIX)


def title(event):
    user = event.deep_get("actor", "alternateId") or "unknown user"
    source_ip = event.deep_get("client", "ipAddress") or "unknown IP"
    user_agent = event.deep_get("client", "userAgent", "rawUserAgent") or "unknown client"
    return f"Okta legacy API auth without MFA: {user} from {source_ip} [{user_agent}]"


def severity(event):
    user_agent = (event.deep_get("client", "userAgent", "rawUserAgent") or "").lower()
    if any(kw in user_agent for kw in AUTOMATION_KEYWORDS):
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return okta_alert_context(event)
