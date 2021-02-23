from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup


def rule(event):
    if deep_get(event, "id", "applicationName") != "user_accounts":
        return False

    return bool(details_lookup("titanium_change", ["titanium_unenroll"], event))


def title(event):
    return (
        f"Advanced protection was disabled for user "
        f"[{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )
