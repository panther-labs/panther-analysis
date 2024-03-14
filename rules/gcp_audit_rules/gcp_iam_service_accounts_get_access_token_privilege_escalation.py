from gcp_base_helpers import gcp_alert_context
from panther_base_helpers import deep_walk


def rule(event):
    authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
    if not authorization_info:
        return False

    for auth in authorization_info:
        if (
            auth.get("permission") == "iam.serviceAccounts.getAccessToken"
            and auth.get("granted") is True
        ):
            return True
    return False


def alert_context(event):
    return gcp_alert_context(event)
