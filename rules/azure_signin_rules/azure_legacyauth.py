import json
from unittest.mock import MagicMock

from global_filter_azuresignin import filter_include_event
from panther_azuresignin_helpers import actor_user, azure_signin_alert_context
from panther_base_helpers import deep_get

LEGACY_AUTH_USERAGENTS = ["BAV2ROPC", "CBAInPROD"]  # CBAInPROD is reported to be IMAP

# Add ServicePrincipalName/UserPrincipalName to
# KNOWN_EXCEPTIONS to prevent these Principals from Alerting
KNOWN_EXCEPTIONS = []


def rule(event):
    global KNOWN_EXCEPTIONS  # pylint: disable=global-statement
    if isinstance(KNOWN_EXCEPTIONS, MagicMock):
        KNOWN_EXCEPTIONS = json.loads(KNOWN_EXCEPTIONS())  # pylint: disable=not-callable
    if not filter_include_event(event):
        return False
    if actor_user(event) in KNOWN_EXCEPTIONS:
        return False
    user_agent = deep_get(event, "properties", "userAgent", default="")
    error_code = deep_get(event, "properties", "status", "errorCode", default=0)

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
    a_c["userAgent"] = deep_get(event, "properties", "userAgent", "<NO_USERAGENT>")
    return a_c
