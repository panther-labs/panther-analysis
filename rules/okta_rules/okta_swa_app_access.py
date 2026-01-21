from panther_base_helpers import get_val_from_list
from panther_okta_helpers import okta_alert_context


def rule(event):
    if event.get("eventType") == "policy.evaluate_sign_on":
        outcome = event.deep_get("outcome", "result", default="")
        if outcome == "SUCCESS":
            sign_on_mode = event.deep_get("debugContext", "debugData", "signOnMode", default="")
            if sign_on_mode == "BROWSER_PLUGIN":
                return True
    return False


def title(event):
    actor = event.deep_get("actor", "alternateId", default="<UNKNOWN_ACTOR>")
    app_names = get_val_from_list(event.get("target", [{}]), "displayName", "type", "AppInstance")
    app_name = list(app_names)[0] if app_names else "<UNKNOWN_APP>"

    return f"Okta SWA Application Access: {actor} accessed [{app_name}]"


def alert_context(event):
    context = okta_alert_context(event)

    app_names = get_val_from_list(event.get("target", [{}]), "displayName", "type", "AppInstance")
    context["app_name"] = list(app_names)[0] if app_names else "<UNKNOWN_APP>"

    app_ids = get_val_from_list(event.get("target", [{}]), "alternateId", "type", "AppInstance")
    context["app_id"] = list(app_ids)[0] if app_ids else "<UNKNOWN_APP_ID>"

    context["timestamp"] = event.get("published", "")
    context["user_agent"] = event.deep_get("client", "userAgent", "rawUserAgent", default="")

    return context
