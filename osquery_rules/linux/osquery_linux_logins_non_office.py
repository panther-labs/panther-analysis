import ipaddress

# Note: The IP Network below is only an example
OFFICE_NETWORK = ipaddress.ip_network('192.0.1.0/24')


# TODO: Switch this to the `last` query and check the epoch to make sure they are new logins.
def rule(event):
    if event['action'] != 'added':
        return False

    if 'logged_in_users' not in event['name']:
        return False

    host_ip = event['columns'].get('host')
    if not host_ip:
        return False

    if ipaddress.IPv4Address(host_ip) not in OFFICE_NETWORK.hosts():
        return True

    return False


def dedup(event):
    # Dedup by user to view lateral movement
    return event['columns'].get('user')


def title(event):
    return 'User {} has logged into production from a non-office network'.format(
        event['columns'].get('user', '<USER_NOT_FOUND>'))
