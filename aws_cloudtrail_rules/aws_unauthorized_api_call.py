from ipaddress import ip_address
from panther_oss_helpers import aws_strip_role_session_id  # pylint disable:import-error


def rule(event):
    # Validate the request came from outside of AWS
    try:
        ip_address(event.get('sourceIPAddress'))
    except ValueError:
        return False
    return event.get('errorCode') == 'AccessDenied'


def dedup(event):
    user_identity = event['userIdentity']
    if user_identity.get('type') == 'AssumedRole':
        return aws_strip_role_session_id(user_identity.get('arn', ''))
    return user_identity.get('arn')


def title(event):
    user_identity = event.get('userIdentity')
    return 'Access denied to {} [{}]'.format(user_identity.get('type'),
                                             dedup(event))
