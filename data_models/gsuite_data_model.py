import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup


def get_event_type(event):
    # currently, only tracking a few event types
    # Pattern match this event to the recon actions
    if deep_get(event, "id", "applicationName") == "admin":
        if bool(details_lookup("DELEGATED_ADMIN_SETTINGS", ["ASSIGN_ROLE"], event)):
            return event_type.ADMIN_ROLE_ASSIGNED
    if details_lookup("login", ["login_failure"], event):
        return event_type.FAILED_LOGIN
    if deep_get(event, "id", "applicationName") == "login":
        return event_type.SUCCESSFUL_LOGIN
    return None
