import re


def rule(event):
    return (event['outcome']['result'] == 'FAILURE' and event['eventType'] == 'user.session.start')


def title(event):
    return 'Suspected brute force Okta logins to account {} due to [{}]'.format(
        event['actor']['alternateId'],
        event['outcome']['reason']
    )
