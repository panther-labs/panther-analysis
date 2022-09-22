from panther_base_helpers import deep_get, lst_iter


def rule(event):
    global target_user
    global target_app_names
    # event['target'] = [{...}, {...}, {...}]
    target_user = lst_iter(
        event.get("target", [{}]), 'alternateId', 'Type', 'AppUser')
    target_app_names = target_app_names = lst_iter(
        event.get("target", [{}]), 'alternateId', 'Type', 'AppInstance')

    if (
        event.get("eventType") != "application.user_membership.show_password"
        or not event.udm("actor_user")
    ):
        return False

    if deep_get(event, 'actor', 'alternateId') not in target_user:
        return True
    return False


def dedup(event):
    dedup_str = deep_get(event, 'actor', 'alternateId')

    if target_user:
        dedup_str += ":" + str(target_user)
    if target_app_names:
        dedup_str += ":" + str(target_app_names)
    return dedup_str or ''


def title(event):
    return (
        f"A user {deep_get(event, 'actor', 'alternateId')} accessed another user's "
        f"{target_user} "
        f"{target_app_names} password"
    )
