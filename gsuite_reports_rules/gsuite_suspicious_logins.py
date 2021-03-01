from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

SUSPICOUS_LOGIN_TYPES = {
    "suspicious_login",
    "suspicious_login_less_secure_app",
    "suspicious_programmatic_login",
}


def rule(event):
    if deep_get(event, "id", "applicationName") != "login":
        return False

    return bool(details_lookup("account_warning", SUSPICOUS_LOGIN_TYPES, event))


def title(event):
    details = details_lookup("account_warning", SUSPICOUS_LOGIN_TYPES, event)
    user = param_lookup(details.get("parameters", {}), "affected_email_address")
    if not user:
        user = "<UNKNOWN_USER>"
    return f"A suspicious login was reported for user [{user}]"
