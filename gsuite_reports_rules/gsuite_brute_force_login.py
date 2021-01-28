from panther_base_helpers import deep_get, gsuite_details_lookup

# pylint: disable=pointless-string-statement
'''
SELECT *
FROM panther_logs.public.gsuite_reports
WHERE id:applicationName = 'login'
AND events[0]:name = 'login_failure' LIMIT 10;
'''


def rule(event):
    # Filter login events
    if deep_get(event, 'id', 'applicationName') != 'login':
        return False

    # Pattern match this event to the recon actions
    return bool(gsuite_details_lookup('login', ['login_failure'], event))


def title(event):
    return 'Brute force login suspected for user [{}]'.format(
        deep_get(event, 'actor', 'email'))
