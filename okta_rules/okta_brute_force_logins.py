from panther_base_helpers import okta_alert_context


def rule(event):
    return (event['outcome']['result'] == 'FAILURE' and
            event['eventType'] == 'user.session.start')


def title(event):
    return 'Suspected brute force Okta logins to account {} due to [{}]'.format(
        event['actor']['alternateId'], event['outcome']['reason'])


def alert_context(event):
    return okta_alert_context(event)
