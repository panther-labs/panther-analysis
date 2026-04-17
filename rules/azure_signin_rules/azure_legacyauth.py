import json
from unittest.mock import MagicMock

from panther_azuresignin_helpers import actor_user, azure_signin_alert_context, is_sign_in_event

LEGACY_AUTH_USERAGENTS = ["BAV2ROPC", "CBAInPROD"]  # CBAInPROD is reported to be IMAP

# Add ServicePrincipalName/UserPrincipalName to
# KNOWN_EXCEPTIONS to prevent these Principals from Alerting
KNOWN_EXCEPTIONS = []


def rule(event):
    if not is_sign_in_event(event):
        return False

    global KNOWN_EXCEPTIONS  # pylint: disable=global-statement
    if isinstance(KNOWN_EXCEPTIONS, MagicMock):
        KNOWN_EXCEPTIONS = json.loads(KNOWN_EXCEPTIONS())  # pylint: disable=not-callable

    if actor_user(event) in KNOWN_EXCEPTIONS:
        return False
    user_agent = event.deep_get("properties", "userAgent", default="")
    error_code = event.deep_get("properties", "status", "errorCode", default=0)

    return all([user_agent in LEGACY_AUTH_USERAGENTS, error_code == 0])


def title(event):
    principal = actor_user(event)
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"
    return f"AzureSignIn: Principal [{principal}] authenticated with a legacy auth protocol"


def dedup(event):
    principal = actor_user(event)
    if principal is None:
        principal = "<NO_PRINCIPALNAME>"
    return principal


def alert_context(event):
    a_c = azure_signin_alert_context(event)
    a_c["userAgent"] = event.deep_get("properties", "userAgent", "<NO_USERAGENT>")
    return a_c
