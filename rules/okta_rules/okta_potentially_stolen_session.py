import json
from datetime import datetime, timedelta
from difflib import SequenceMatcher

from panther_base_helpers import deep_get, okta_alert_context
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration

FUZZ_RATIO_MIN = 0.95
PREVIOUS_SESSION = {}
SESSION_TIMEOUT = 1  # the number of days an Okta session is valid for (configured in Okta)


def rule(event):
    # pylint: disable=global-statement
    # ensure previous session info is avaialable in the alert_context for investigation
    global PREVIOUS_SESSION

    session_id = deep_get(event, "authenticationContext", "externalSessionId", default="")

    # Filter only on app access and session start events
    if (
        event.get("eventType") == "user.authentication.sso"  # user opened app
        or event.get("eventType") == "user.session.start"  # user logged in
    ) and session_id != "unknown":

        # lookup if we've previously stored the session cookie
        PREVIOUS_SESSION = get_string_set(session_id)

        # For unit test mocks we need to eval the string to a set
        if isinstance(PREVIOUS_SESSION, str):
            PREVIOUS_SESSION = set(json.loads(PREVIOUS_SESSION))

        # If the sessionID has not been seen before, store information about it
        if len(PREVIOUS_SESSION) == 0:
            key = session_id
            put_string_set(
                key,
                [
                    str(deep_get(event, "securityContext", "asNumber")),
                    deep_get(event, "client", "ipAddress"),
                    # clearly label the user agent string so we can find it during the comparison
                    "user_agent:" + deep_get(event, "client", "userAgent", "rawUserAgent"),
                    deep_get(event, "client", "userAgent", "browser"),
                    deep_get(event, "client", "userAgent", "os"),
                    event.get("p_event_time"),
                ],
            )
            # Expire the session from the KV store once it is no longer valid within Okta
            set_key_expiration(
                key, str((datetime.now() + timedelta(days=SESSION_TIMEOUT)).timestamp())
            )

        # if the session cookie was seen before
        else:
            # we use a fuzz match to compare the current and prev user agent.
            # We cannot do a direct match since Okta can occasionally maintain
            # a session across browser upgrades.

            # the user-agent was tagged during storage so we can find it, remove that tag
            [prev_ua] = [x for x in PREVIOUS_SESSION if "user_agent:" in x] or ""
            prev_ua = prev_ua.split("_agent:")[1]

            print(prev_ua)

            diff_ratio = SequenceMatcher(
                None, deep_get(event, "client", "userAgent", "rawUserAgent", default=""), prev_ua
            ).ratio()

            # is this session being used from a new ASN and a different browser
            if (
                str(deep_get(event, "securityContext", "asNumber", default=""))
                not in PREVIOUS_SESSION
                and diff_ratio < FUZZ_RATIO_MIN
            ):
                # make the fuzz ratio available in the alert context
                PREVIOUS_SESSION.add("Fuzz Ratio: " + str(diff_ratio))
                return True

    return False


def title(event):
    return (
        f"Potentially Stolen Okta Session - "
        f"{deep_get(event, 'actor', 'displayName', default='Unknown')}"
    )


def alert_context(event):
    context = okta_alert_context(event)
    context["previous_session"] = str(PREVIOUS_SESSION)
    return context
