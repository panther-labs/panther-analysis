def rule(event):
    if event['id'].get('applicationName') != 'groups_enterprise':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'moderator_action' and
                details.get('name') == 'ban_user_with_moderation'):
            return True

    return False


def title(event):
    return 'User [{}] banned another user from a group.'.format(
        event.get('actor', {}).get('email'))
