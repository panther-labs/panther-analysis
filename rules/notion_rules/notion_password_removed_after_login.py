import time
from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context
from panther_oss_helpers import get_string_set, put_string_set


# Length of time in seconds. If a user logs in, then changes their password within this many
# minutes, raise an alert.
DEFAULT_PASSWORD_REMOVE_WINDOW_MINUTES = 10

# Prefix for cached key. This ensures we don't accidently tamper with cached data from other
# detections.
CACHE_PREFIX = "Notion.PasswordRemovedAfterLogin"


def rule(event):
    if not filter_include_event(event):
        return False

    # If this is neither a login, nor password remove event, then exit
    allowed_event_types = {
        "user.login",
        "user.settings.login_method.password_removed",
    }
    if event.deep_walk("event", "type") not in allowed_event_types:
        return False

    # Extract user info
    userid = event.deep_walk("event", "actor", "id")
    cache_key = f"{CACHE_PREFIX}-{userid}"

    # If this is a login event, record it
    if event.deep_walk("event", "type") == "user.login":
        put_string_set(
            cache_key,
            [str(event.get("p_event_time"))],  # We'll save this for the alert context later
            time.time() + DEFAULT_PASSWORD_REMOVE_WINDOW_MINUTES * 60,
        )
        return False

    # If we made it here, then this is a password remove event
    # We first check if the user recently logged in
    if last_login := get_string_set(cache_key, force_ttl_check=True):
        # pylint: disable=global-variable-undefined
        global LOGIN_TS
        LOGIN_TS = list(last_login)[0]  # Save the last login timestamp for the alert context
        return True
    # If they haven't logged in recently, then return false
    return False


def title(event):
    user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNOWN EMAIL")
    mins = DEFAULT_PASSWORD_REMOVE_WINDOW_MINUTES
    return f"User [{user_email}] removed their password within [{mins}] minutes of logging in."


def alert_context(event):
    context = notion_alert_context(event)
    global LOGIN_TS
    context["login_timestamp"] = LOGIN_TS
    return context