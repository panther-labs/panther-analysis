AUTOMATION_KEYWORDS = ["python", "curl", "requests", "powershell", "urllib", "okta-sdk"]


def rule(event):
    # The scheduled query has already filtered to legacy '102'-prefix sessions
    # with no matching user.authentication.auth_via_mfa event in the same chain.
    # Guard against malformed rows missing the primary keys.
    return bool(event.get("user_email")) and bool(event.get("external_session_id"))


def title(event):
    user = event.get("user_email") or "unknown user"
    source_ip = event.get("source_ip") or "unknown IP"
    user_agent = event.get("user_agent") or "unknown client"
    return f"Okta legacy API auth without MFA: {user} from {source_ip} [{user_agent}]"


def severity(event):
    user_agent = (event.get("user_agent") or "").lower()
    if any(kw in user_agent for kw in AUTOMATION_KEYWORDS):
        return "HIGH"
    return "DEFAULT"


def alert_context(event):
    return {
        "user_email": event.get("user_email"),
        "actor_id": event.get("actor_id"),
        "source_ip": event.get("source_ip"),
        "user_agent": event.get("user_agent"),
        "external_session_id": event.get("external_session_id"),
        "transaction_id": event.get("transaction_id"),
        "request_uri": event.get("request_uri"),
        "session_start_time": event.get("session_start_time"),
    }


def dedup(event):
    return event.get("external_session_id") or "unknown_session"
