from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup


def rule(event):
    if deep_get(event, "id", "applicationName") != "mobile":
        return False

    return bool(details_lookup("suspicious_activity", ["SUSPICIOUS_ACTIVITY_EVENT"], event))


def title(event):
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]"
        f"'s device was compromised"
    )
