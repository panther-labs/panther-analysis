from panther_base_helpers import gsuite_details_lookup as details_lookup


def rule(event):
    if event['id'].get('applicationName') != 'login':
        return False

    return bool(details_lookup('attack_warning', ['gov_attack_warning'], event))


def title(event):
    return 'User [{}] may have been targeted by a government attack'.format(
        event.get('actor', {}).get('email'))
