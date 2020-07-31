from fnmatch import fnmatch
from ipaddress import ip_address

# TODO change to native thresholding once support is added
# tentatively slated for 1.7
THRESH = 10
THRESH_TTL = 600  # 10 minutes


def rule(event):
    # Filter events
    if event['id'].get('applicationName') != 'login':
        return False

    # Pattern match this event to the recon actions
    for detail in event.get('events', [{}]):
        if detail.get('type') == 'login' and detail.get(
                'name') == 'login_failure':
            from panther_oss_helpers import evaluate_threshold  # pylint: disable=import-error
            return evaluate_threshold(
                '{}-GSuiteLoginFailedCounter'.format(
                    event.get('actor', {}).get('email')),
                THRESH,
                THRESH_TTL,
            )

    return False


def dedup(event):
    return event.get('actor', {}).get('email')


def title(event):
    return 'User [{}] exceeded the failed logins threshold'.format(
        event.get('actor', {}).get('email'))
