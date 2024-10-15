import json
from datetime import timedelta
from difflib import SequenceMatcher

from panther_base_helpers import okta_alert_context
from panther_detection_helpers.caching import get_string_set, put_string_set

FUZZ_RATIO_MIN = 0.95
PREVIOUS_SESSION = {}
# the number of days an Okta session is valid for (configured in Okta)
SESSION_TIMEOUT = timedelta(days=1).total_seconds()
EVENT_TYPES = ("user.authentication.sso", "user.session.start")


def rule(event):
    # pylint: disable=global-statement
    # ensure previous session info is avaialable in the alert_context for investigation
    global PREVIOUS_SESSION

    session_id = event.deep_get("authenticationContext", "externalSessionId", default="unknown")
    dt_hash = event.deep_get("debugContext", "debugData", "dtHash", default="unknown")

    # Some events by Okta admins may appear to have changed IPs
    # and user agents due to internal Okta behavior:
    # https://support.okta.com/help/s/article/okta-integrations-showing-as-rawuseragent-with-okta-ips
    # As such, we ignore certain client ids known to originate from Okta:
    # https://developer.okta.com/docs/api/openapi/okta-myaccount/myaccount/tag/OktaApplications/
    if event.deep_get("client", "id") in [
        "okta.b58d5b75-07d4-5f25-bf59-368a1261a405"  # Admin Console
    ]:
        return False

    # Filter only on app access and session start events
    if event.get("eventType") not in EVENT_TYPES or (
        session_id == "unknown" or dt_hash == "unknown"
    ):
        return False

    key = session_id + "-" + dt_hash

    # lookup if we've previously stored the session cookie
    PREVIOUS_SESSION = get_string_set(key)

    # For unit test mocks we need to eval the string to a set
    if isinstance(PREVIOUS_SESSION, str):
        PREVIOUS_SESSION = set(json.loads(PREVIOUS_SESSION))

    # If the sessionID has not been seen before, store information about it
    if not PREVIOUS_SESSION:
        put_string_set(
            key,
            [
                str(event.deep_get("securityContext", "asNumber")),
                event.deep_get("client", "ipAddress"),
                # clearly label the user agent string so we can find it during the comparison
                "user_agent:" + event.deep_get("client", "userAgent", "rawUserAgent"),
                event.deep_get("client", "userAgent", "browser"),
                event.deep_get("client", "userAgent", "os"),
                event.get("p_event_time"),
                "sign_on_mode:"
                + event.deep_get("debugContext", "debugData", "signOnMode", default="unknown"),
                "threat_suspected:"
                + event.deep_get(
                    "debugContext", "debugData", "threat_suspected", default="unknown"
                ),
            ],
            epoch_seconds=event.event_time_epoch() + SESSION_TIMEOUT,
        )

    # if the session cookie was seen before
    else:
        # we use a fuzz match to compare the current and prev user agent.
        # We cannot do a direct match since Okta can occasionally maintain
        # a session across browser upgrades.

        # the user-agent was tagged during storage so we can find it, remove that tag
        [prev_ua] = [x for x in PREVIOUS_SESSION if "user_agent:" in x] or ["prev_ua_not_found"]
        prev_ua = prev_ua.split("_agent:")[1]

        diff_ratio = SequenceMatcher(
            None,
            event.deep_get("client", "userAgent", "rawUserAgent", default="ua_not_found"),
            prev_ua,
        ).ratio()

        # is this session being used from a new IP and a different browser
        if (
            str(event.deep_get("client", "ipAddress", default="ip_not_found"))
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
        f"{event.deep_get('actor', 'displayName', default='Unknown_user')}"
    )


def alert_context(event):
    context = okta_alert_context(event)
    context["previous_session"] = str(PREVIOUS_SESSION)
    return context
