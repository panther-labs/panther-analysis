from ipaddress import ip_address
from panther_oss_helpers import aws_strip_role_session_id

# Do not alert on these access denied errors for these events.
# Events could be exceptions because they are particularly noisy and provide little to no value,
# or because they are expected as part of the normal operating procedure for certain tools.
EVENT_EXCEPTIONS = {
    'DescribeEventAggregates',  # Noisy, doesn't really provide any actionable info
    'ListResourceTags',  # The audit role hits this when scanning locked down resources
}


def rule(event):
    # Validate the request came from outside of AWS
    try:
        ip_address(event.get('sourceIPAddress'))
    except ValueError:
        return False
    return event.get('errorCode') == 'AccessDenied' and event[
        'eventName'] not in EVENT_EXCEPTIONS


def dedup(event):
    user_identity = event['userIdentity']
    if user_identity.get('type') == 'AssumedRole':
        return aws_strip_role_session_id(user_identity.get('arn', ''))
    return user_identity.get('arn', '')


def title(event):
    user_identity = event.get('userIdentity')
    return 'Access denied to {} [{}]'.format(user_identity.get('type'),
                                             dedup(event))
