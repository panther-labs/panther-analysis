from panther_base_helpers import deep_get
from panther_base_helpers import gsuite_details_lookup as details_lookup


def rule(event):
    if deep_get(event, "id", "applicationName") != "groups_enterprise":
        return False

    return bool(details_lookup("moderator_action", ["ban_user_with_moderation"], event))


def title(event):
    return (
        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] "
        f"banned another user from a group."
    )
