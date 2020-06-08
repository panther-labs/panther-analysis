from ipaddress import ip_address


def rule(event):
    # Validate the request came from outside of AWS
    try:
        ip_address(event.get('sourceIPAddress'))
    except ValueError:
        return False
    return event.get('errorCode') == 'AccessDenied' and event[
        'eventName'] != 'DescribeEventAggregates'


def helper_strip_role_session_id(user_identity_arn):
    # The Arn structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split('/')
    if arn_parts:
        return '/'.join(arn_parts[:2])
    return user_identity_arn


def dedup(event):
    user_identity = event['userIdentity']
    if user_identity.get('type') == 'AssumedRole':
        return helper_strip_role_session_id(user_identity.get('arn', ''))
    return user_identity.get('arn')


def title(event):
    user_identity = event.get('userIdentity')
    return 'Access denied to {} {}'.format(user_identity.get('type'),
                                           dedup(event))
