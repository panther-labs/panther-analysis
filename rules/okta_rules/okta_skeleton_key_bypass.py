from panther_base_helpers import get_val_from_list
from panther_okta_helpers import okta_alert_context

# Suspicious user-agent patterns indicating automation/scripting tools
SUSPICIOUS_USER_AGENTS = [
    "python",
    "curl",
    "wget",
    "postman",
    "httpie",
    "rest-client",
    "insomnia",
    "axios",
    "requests",
    "okhttp",
]


def rule(event):
    if event.get("eventType") == "user.authentication.sso":
        outcome = event.deep_get("outcome", "result", default="")
        if outcome == "SUCCESS":
            device = event.deep_get("client", "device", default="")
            if device.lower() == "unknown":
                user_agent = event.deep_get(
                    "client", "userAgent", "rawUserAgent", default=""
                ).lower()
                if any(pattern in user_agent for pattern in SUSPICIOUS_USER_AGENTS):
                    return True

    return False


def title(event):
    actor = event.deep_get("actor", "alternateId", default="<UNKNOWN_ACTOR>")
    app_names = get_val_from_list(
        event.get("target", [{}]), "displayName", "type", "AppInstance"
    )
    app_name = list(app_names)[0] if app_names else "<UNKNOWN_APP>"
    user_agent = event.deep_get(
        "client", "userAgent", "rawUserAgent", default="<UNKNOWN_USER_AGENT>"
    )

    return f"Okta Authentication Bypass: {actor} accessed [{app_name}] via [{user_agent}]"


def severity(event):
    user_agent = event.deep_get("client", "userAgent", "rawUserAgent", default="").lower()

    if any(pattern in user_agent for pattern in ["python", "curl", "wget"]):
        return "HIGH"

    return "DEFAULT"


def alert_context(event):
    context = okta_alert_context(event)

    context["user_agent"] = event.deep_get("client", "userAgent", "rawUserAgent", default="")
    context["device_type"] = event.deep_get("client", "device", default="")
    context["app_target"] = event.get("target", [])

    return context
