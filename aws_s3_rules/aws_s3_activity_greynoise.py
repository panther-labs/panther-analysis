from ipaddress import ip_address

from panther import lookup_aws_account_name
from panther_base_helpers import deep_get
from panther_greynoise_helpers import GetGreyNoiseObject, GetGreyNoiseRiotObject


def rule(event):
    # Filter: Non-S3 events
    if event.get('eventSource') != 's3.amazonaws.com':
        return False
    # Filter: Errors
    if event.get('errorCode'):
        return False
    # Filter: Internal AWS
    if deep_get(event, 'userIdentity', 'type') in ('AWSAccount', 'AWSService'):
        return False

    # Validate the IP is actually an IP (sometimes it's a string)
    try:
        ip_address(event.get('sourceIPAddress'))
    except ValueError:
        return False

    # Create GreyNoise Objects
    global noise
    noise = GetGreyNoiseObject(event)
    riot = GetGreyNoiseRiotObject(event)

    # If IP is in RIOT dataset we can assume safe, do not alert
    if riot.is_riot('sourceIPAddress'):
        return False

    # Check that the IP is classified as 'malicious'
    if noise.classification('sourceIPAddress') == 'malicious':
        return True
    return False


def title(event):
    # Group by ip-arn combinations
    ip = deep_get(event, 'sourceIPAddress')
    arn = deep_get(event, 'userIdentity', 'arn')
    aws_account = deep_get(event, 'recipientAccountId')
    return f'GreyNoise malicious S3 events detected by {ip} in AWS Account {aws_account} from {arn}'


def alert_context(event):
    return noise.context('sourceIPAddress')

