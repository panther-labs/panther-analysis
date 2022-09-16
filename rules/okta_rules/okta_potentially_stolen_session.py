from ast import literal_eval
from datetime import datetime, timedelta

from panther_base_helpers import deep_get, okta_alert_context
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration
from thefuzz import fuzz

PREVIOUS_SESSION = {}
FUZZ_RATIO_MIN = 95


def rule(event):
    # pylint: disable=global-statement
    # ensure previous session info is avaialable in the alert_context for investigation
    global PREVIOUS_SESSION

    # Filter only on app access and session start events
    if (
        event.get("eventType") == "user.authentication.sso"  # user opened app
        or event.get("eventType") == "user.session.start"  # user loged in
    ):

        # lookup if we've previously stored the session cookie
        PREVIOUS_SESSION = get_string_set(
            deep_get(event, "authenticationContext", "externalSessionId"),
        )

        # For unit test mocks we need to eval the string to a set
        if isinstance(PREVIOUS_SESSION, str):
            PREVIOUS_SESSION = literal_eval(PREVIOUS_SESSION)

        # if the session cookie was seen before
        if PREVIOUS_SESSION is not None:
            # we use a fuzz match to compare the current and prev user agent.
            # We cannot do a direct match since Okta can occasionally maintain
            # a session across browser upgrades.

            # the user-agent is the longest string in the set
            prev_ua = next(x for x in PREVIOUS_SESSION if len(x) > 25)
            fuzz_ratio = fuzz.ratio(
                deep_get(event, "client", "userAgent", "rawUserAgent", default=""), prev_ua
            )

            # is this session being used from a new ASN and a different browser
            if (
                str(deep_get(event, "securityContext", "asNumber", default=""))
                not in PREVIOUS_SESSION
                and fuzz_ratio < FUZZ_RATIO_MIN
            ):
                # make the fuzz ratio available in the alert context
                PREVIOUS_SESSION.add("Fuzz Ratio: " + str(fuzz_ratio))
                return True

        # If the sessionID has not been seen before, store information about it
        else:
            key = deep_get(event, "authenticationContext", "externalSessionId")
            put_string_set(
                key,
                [
                    str(deep_get(event, "securityContext", "asNumber")),
                    deep_get(event, "client", "ipAddress"),
                    deep_get(event, "client", "userAgent", "rawUserAgent"),
                    deep_get(event, "client", "userAgent", "browser"),
                    deep_get(event, "client", "userAgent", "os"),
                    event.get("p_event_time"),
                ],
            )
            set_key_expiration(key, str((datetime.now() + timedelta(days=2)).timestamp()))

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
