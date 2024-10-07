from panther_base_helpers import get_val_from_list

# pylint: disable=global-variable-undefined


def rule(event):
    global TARGET_USERS
    global TARGET_APP_NAMES

    if event.get("eventType") != "application.user_membership.show_password":
        return False

    # event['target'] = [{...}, {...}, {...}]
    TARGET_USERS = get_val_from_list(event.get("target", [{}]), "alternateId", "type", "User")
    TARGET_APP_NAMES = get_val_from_list(
        event.get("target", [{}]), "alternateId", "type", "AppInstance"
    )

    if event.deep_get("actor", "alternateId") not in TARGET_USERS:
        return True
    return False


def dedup(event):
    dedup_str = event.deep_get("actor", "alternateId")

    if TARGET_USERS:
        dedup_str += ":" + str(TARGET_USERS)
    if TARGET_APP_NAMES:
        dedup_str += ":" + str(TARGET_APP_NAMES)
    return dedup_str or ""


def title(event):
    return (
        f"A user {event.deep_get('actor', 'alternateId')} accessed another user's "
        f"{TARGET_USERS} "
        f"{TARGET_APP_NAMES} password"
    )
