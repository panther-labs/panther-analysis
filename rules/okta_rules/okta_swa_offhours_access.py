from datetime import datetime

from panther_base_helpers import get_val_from_list
from panther_okta_helpers import okta_alert_context

BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 18


def get_app_name(event):
    # Extract app name from target based on event type
    event_type = event.get("eventType", "")
    # Password reveal events use alternateId, sign-on events use displayName
    field = (
        "alternateId"
        if event_type == "application.user_membership.show_password"
        else "displayName"
    )
    app_names = get_val_from_list(event.get("target", [{}]), field, "type", "AppInstance")
    return list(app_names)[0] if app_names else "<UNKNOWN_APP>"


def rule(event):
    event_type = event.get("eventType", "")

    if event_type == "application.user_membership.show_password":
        return is_outside_business_hours(event)

    if event_type == "policy.evaluate_sign_on":
        outcome = event.deep_get("outcome", "result", default="")
        if outcome == "SUCCESS":
            sign_on_mode = event.deep_get("debugContext", "debugData", "signOnMode", default="")
            if sign_on_mode == "BROWSER_PLUGIN":
                return is_outside_business_hours(event)

    return False


def is_outside_business_hours(event):
    timestamp = event.get("published", "")
    if not timestamp:
        return False

    try:
        event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        hour = event_time.hour

        if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
            return True
    except (ValueError, AttributeError):
        return False

    return False


def title(event):
    actor = event.deep_get("actor", "alternateId", default="<UNKNOWN_ACTOR>")
    event_type = event.get("eventType", "")
    timestamp = event.get("published", "<UNKNOWN_TIME>")
    app_name = get_app_name(event)

    if event_type == "application.user_membership.show_password":
        return f"Okta SWA Off-Hours Password Access: {actor} accessed [{app_name}] at [{timestamp}]"

    return f"Okta SWA Off-Hours Application Access: {actor} accessed [{app_name}] at [{timestamp}]"


def severity(event):
    timestamp = event.get("published", "")
    if not timestamp:
        return "DEFAULT"

    try:
        event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        hour = event_time.hour

        # Late night access (10 PM - 4 AM UTC) is highest risk - likely unauthorized
        if 22 <= hour or hour < 4:
            return "HIGH"

        # Early morning (4 AM - 8 AM) or evening (6 PM - 10 PM) is medium risk
        if (4 <= hour < BUSINESS_HOURS_START) or (BUSINESS_HOURS_END <= hour < 22):
            return "MEDIUM"

    except (ValueError, AttributeError):
        return "DEFAULT"

    return "DEFAULT"


def alert_context(event):
    context = okta_alert_context(event)

    timestamp = event.get("published", "")
    context["event_timestamp"] = timestamp

    if timestamp:
        try:
            event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            context["event_hour_utc"] = event_time.hour
            context["event_weekday"] = event_time.strftime("%A")
        except (ValueError, AttributeError):
            context["event_hour_utc"] = "<PARSE_ERROR>"
            context["event_weekday"] = "<PARSE_ERROR>"

    event_type = event.get("eventType", "")
    context["event_type"] = event_type
    context["app_name"] = get_app_name(event)
    context["business_hours"] = f"{BUSINESS_HOURS_START}:00 - {BUSINESS_HOURS_END}:00 UTC"
    context["user_agent"] = event.deep_get("client", "userAgent", "rawUserAgent", default="")

    return context
