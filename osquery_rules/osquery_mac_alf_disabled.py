def rule(event):
    return (
        event['name'] == ('pack_incident-response_alf') and
        # 1 If the firewall is enabled with exceptions
        # 2 if the firewall is configured to block all incoming connections, else 0
        int(event['columns']['global_state']) == 0 and
        event['action'] == 'added')


def dedup(event):
    return event.get('hostIdentifier')


def title(event):
    'Mac Firewall Disabled on {}'.format(event.get('hostIdentifier'))
