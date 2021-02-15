from panther_base_helpers import deep_get, okta_alert_context  # pylint: disable=import-error


def rule(event):
    return (event.get('eventType', None) == 'system.api_token.create' and
            deep_get(event, 'outcome', 'result') == 'SUCCESS')

def title(event):
    title_str = '{} <{}> created a new API key [{}]'

    target = event.get('target', [{}])
    display_name = target[0].get('displayName', 'MISSING DISPLAY NAME') if target else 'MISSING TARGET'

    return title_str.format(
        deep_get(event, 'actor', 'displayName'),
        deep_get(event, 'actor', 'alternateId'),
        display_name)


def alert_context(event):
    return okta_alert_context(event)
