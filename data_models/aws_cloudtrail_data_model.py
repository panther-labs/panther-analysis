import ipaddress
import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get


def get_event_type(event):
    # currently, only tracking a few event types
    if event.get('eventName') == 'ConsoleLogin' and deep_get(
            event, 'userIdentity', 'type') == 'IAMUser':
        if deep_get(event, 'responseElements', 'ConsoleLogin') == 'Failure':
            return event_type.FAILED_LOGIN
        if deep_get(event, 'responseElements', 'ConsoleLogin') == 'Success':
            return event_type.SUCCESSFUL_LOGIN
    return None


def load_ip_address(event):
    '''
    CloudTrail occassionally sets non-IPs in the sourceIPAddress field.
    This method ensures that either an IPv4 or IPv6 address is always returned.
    '''
    source_ip = event.get('sourceIPAddress')
    if not source_ip:
        return None
    try:
        ip = ipaddress.IPv4Address(source_ip)
    except ipaddress.AddressValueError:
        try:
            ip = ipaddress.IPv6Address(source_ip)
        except ipaddress.AddressValueError:
            return None
    return ip
