from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup


def rule(event):
    if deep_get(event, "id", "applicationName") != "login":
        return False

    return bool(details_lookup("attack_warning", ["gov_attack_warning"], event))


def title(event):
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] may have been "
        f"targeted by a government attack"
    )
