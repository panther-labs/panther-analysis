import re
from panther_base_helpers import deep_get, okta_alert_context  # pylint: disable=import-error


def rule(event):
    return (event['eventType'] == 'user.account.privilege.grant' and
            deep_get(event, 'outcome', 'result') == 'SUCCESS' and bool(
                re.search(
                    r'[aA]dministrator',
                    deep_get(event, 'debugContext', 'debugData',
                             'privilegeGranted'))))


def dedup(event):
    request_id = deep_get(event, 'debugContext', 'debugData', 'requestId')
    return f'requestId-{request_id}'


def title(event):
    title_str = '{} <{}> granted [{}] privileges to {} <{}>'

    target = event.get('target', [])
    display_name = target[0]['displayName'] if target else ''
    alternate_id = target[0]['alternateId'] if target else ''

    return title_str.format(
        deep_get(event, 'actor', 'displayName'),
        deep_get(event, 'actor', 'alternateId'),
        deep_get(event,
                 'debugContext',
                 'debugData',
                 'privilegeGranted',
                 default='PRIV_NOT_FOUND'), display_name, alternate_id)


def alert_context(event):
    return okta_alert_context(event)
