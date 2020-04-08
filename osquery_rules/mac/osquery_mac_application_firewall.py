QUERIES = {'pack_incident-response_alf', 'pack/mac-cis/ApplicationFirewall'}


def rule(event):
    if event['name'] not in QUERIES:
        return False

    if event['action'] != 'added':
        return False

    return (
        # 0 If the firewall is disabled
        # 1 If the firewall is enabled with exceptions
        # 2 If the firewall is configured to block all incoming connections
        int(event['columns'].get('global_state')) == 0 or
        # Stealth mode is a best practice to avoid responding to unsolicted probes
        int(event['columns'].get('stealth_enabled')) == 0)


def dedup(event):
    return event.get('hostIdentifier')


def title(event):
    return 'MacOS firewall disabled on {}'.format(event.get('hostIdentifier'))
