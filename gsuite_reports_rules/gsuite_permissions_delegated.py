from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

PERMISSION_DELEGATED_EVENTS = {
    "ASSIGN_ROLE",
}


def rule(event):
    if deep_get(event, "id", "applicationName") != "admin":
        return False

    return bool(details_lookup("DELEGATED_ADMIN_SETTINGS", PERMISSION_DELEGATED_EVENTS, event))


def title(event):
    details = details_lookup("DELEGATED_ADMIN_SETTINGS", PERMISSION_DELEGATED_EVENTS, event)
    role = param_lookup(details.get("parameters", {}), "ROLE_NAME")
    user = param_lookup(details.get("parameters", {}), "USER_EMAIL")
    if not role:
        role = "<UNKNOWN_ROLE>"
    if not user:
        user = "<UNKNOWN_USER>"
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}] delegated new"
        f" administrator privileges [{role}] to [{user}]"
    )
