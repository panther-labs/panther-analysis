def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'attack_warning' and
                details.get('name') == 'gov_attack_warning'):
            return True

    return False


def title(event):
    return 'User [{}] may have been targeted by a government attack'.format(
        event.get('actor', {}).get('email'))
