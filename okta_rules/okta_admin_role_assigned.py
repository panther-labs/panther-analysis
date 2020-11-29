import re


def rule(event):
    return (
        event['eventType'] == 'user.account.privilege.grant' and
        event['outcome'].get('result', '') == 'SUCCESS' and bool(
            re.search(
                r'[aA]dministrator',
                event['debugContext']['debugData'].get('privilegeGranted'))))


def title(event):
    title_str = '{} <{}> granted [{}] privileges to {} <{}>'
    return title_str.format(
        event['actor']['displayName'], event['actor']['alternateId'],
        event['debugContext']['debugData'].get('privilegeGranted',
                                               'PRIV_NOT_FOUND'),
        event['target'][0]['displayName'], event['target'][0]['alternateId'])


def alert_context(event):
    return {
        'ips': event.get('p_any_ip_addresses', []),
        'actor': event['actor'],
        'target': event['target'],
        'client': event['client'],
    }
