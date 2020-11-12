from panther_base_helpers import gsuite_details_lookup as details_lookup


def rule(event):
    if event['id'].get('applicationName') != 'groups_enterprise':
        return False

    return bool(
        details_lookup('moderator_action', ['ban_user_with_moderation'], event))


def title(event):
    return 'User [{}] banned another user from a group.'.format(
        event.get('actor', {}).get('email'))
