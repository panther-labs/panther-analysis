from panther_base_helpers import deep_get, okta_alert_context  # pylint: disable=import-error


def rule(event):
    return (deep_get(event, 'outcome', 'result') == 'FAILURE' and
            event['eventType'] == 'user.session.start')


def title(event):
    return 'Suspected brute force Okta logins to account {} due to [{}]'.format(
        deep_get(event, 'actor', 'alternateId'),
        deep_get(event, 'outcome', 'reason'))


def alert_context(event):
    return okta_alert_context(event)
