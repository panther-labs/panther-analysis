from panther_base_helpers import gsuite_parameter_lookup as param_lookup


def rule(event):
    if event['id'].get('applicationName') != 'mobile':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'suspicious_activity' and
                details.get('name') == 'DEVICE_COMPROMISED_EVENT' and
                param_lookup(details.get('parameters', {}),
                             'DEVICE_COMPROMISED_STATE') == 'COMPROMISED'):
            return True

    return False


def title(event):
    return 'User [{}]\'s device was compromised'.format(
        event.get('actor', {}).get('email'))
