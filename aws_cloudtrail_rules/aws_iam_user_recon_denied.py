from fnmatch import fnmatch
from ipaddress import ip_address
from panther_oss_helpers import evaluate_threshold  # pylint: disable=import-error

# service/event patterns to monitor
RECON_ACTIONS = {
    'dynamodb': ['List*', 'Describe*', 'Get*'],
    'ec2': ['Describe*', 'Get*'],
    'iam': ['List*', 'Get*'],
    's3': ['List*', 'Get*'],
    'rds': ['Describe*', 'List*'],
}
THRESH = 10
THRESH_TTL = 600  # 10 minutes


def rule(event):
    # Filter events
    if event.get('errorCode') != 'AccessDenied':
        return False
    if event['userIdentity'].get('type') != 'IAMUser':
        return False

    # Validate the request came from outside of AWS
    try:
        ip_address(event.get('sourceIPAddress'))
    except ValueError:
        return False

    # Pattern match this event to the recon actions
    for event_source, event_patterns in RECON_ACTIONS.items():
        if event['eventSource'].startswith(event_source) and any(
                fnmatch(event['eventName'], event_pattern)
                for event_pattern in event_patterns):
            return True

    # Return an alert if the threshold was exceeded
    return evaluate_threshold(
        '{}-AccessDeniedCounter'.format(event['userIdentity'].get('arn')),
        THRESH,
        THRESH_TTL,
    )


def dedup(event):
    return event['userIdentity']['arn']


def title(event):
    user_identity = event.get('userIdentity')
    return 'Reconnaisance activity denied to {} [{}]'.format(
        user_identity.get('type'), dedup(event))
