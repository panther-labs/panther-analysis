QUERIES = {'pack_incident-response_alf', 'pack/mac-cis/ApplicationFirewall'}


def rule(event):
    return (
        event['name'] in QUERIES and
        # 1 If the firewall is enabled with exceptions
        # 2 if the firewall is configured to block all incoming connections, else 0
        int(event['columns'].get('global_state')) == 0 and
        event['action'] == 'added')


def dedup(event):
    return event.get('hostIdentifier')


def title(event):
    return 'MacOS firewall disabled on {}'.format(event.get('hostIdentifier'))
