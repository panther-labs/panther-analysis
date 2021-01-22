from fnmatch import fnmatch
from ipaddress import ip_address
from panther_base_helpers import deep_get

# service/event patterns to monitor
RECON_ACTIONS = {
    'dynamodb': ['List*', 'Describe*', 'Get*'],
    'ec2': ['Describe*', 'Get*'],
    'iam': ['List*', 'Get*'],
    's3': ['List*', 'Get*'],
    'rds': ['Describe*', 'List*'],
}


def rule(event):
    # Filter events
    if event.get('errorCode') != 'AccessDenied':
        return False
    if deep_get(event, 'userIdentity', 'type') != 'IAMUser':
        return False

    # Validate the request came from outside of AWS
    try:
        ip_address(event.get('sourceIPAddress'))
    except ValueError:
        return False

    # Pattern match this event to the recon actions
    for event_source, event_patterns in RECON_ACTIONS.items():
        if event.get('eventSource', '').startswith(event_source) and any(
                fnmatch(event.get('eventName', ''), event_pattern)
                for event_pattern in event_patterns):
            return True
    return False


def dedup(event):
    return event['userIdentity'].get('arn')


def title(event):
    user_identity = event.get('userIdentity')
    return 'Reconnaisance activity denied to {} [{}]'.format(
        user_identity.get('type'), dedup(event))
