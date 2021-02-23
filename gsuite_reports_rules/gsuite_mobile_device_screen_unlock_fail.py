from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

MAX_UNLOCK_ATTEMPTS = 10


def rule(event):
    if deep_get(event, "id", "applicationName") != "mobile":
        return False

    details = details_lookup("suspicious_activity", ["FAILED_PASSWORD_ATTEMPTS_EVENT"], event)
    attempts = param_lookup(details.get("parameters", {}), "FAILED_PASSWD_ATTEMPTS")
    return int(attempts if attempts else 0) > MAX_UNLOCK_ATTEMPTS


def title(event):
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
        f"'s device had multiple failed unlock attempts"
    )
