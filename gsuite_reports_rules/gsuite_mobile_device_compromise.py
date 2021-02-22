from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup


def rule(event):
    if deep_get(event, "id", "applicationName") != "mobile":
        return False

    details = details_lookup("suspicious_activity", ["DEVICE_COMPROMISED_EVENT"], event)
    return (
        bool(details)
        and param_lookup(details.get("parameters", {}), "DEVICE_COMPROMISED_STATE") == "COMPROMISED"
    )


def title(event):
    return f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]'s device was compromised"
