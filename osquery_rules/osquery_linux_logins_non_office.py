import ipaddress

# This is only an example network, but you can set it to whatever you'd like
OFFICE_NETWORKS = [
    ipaddress.ip_network('192.168.1.100/32'),
    ipaddress.ip_network('192.168.1.200/32')
]


def _login_from_non_office_network(host):
    host_ipaddr = ipaddress.IPv4Address(host)

    non_office_logins = []
    for office_network in OFFICE_NETWORKS:
        non_office_logins.append(host_ipaddr in office_network)

    return not any(non_office_logins)


def rule(event):
    if event['action'] != 'added':
        return False

    if 'logged_in_users' in event['name']:
        # Only pay attention to users and not system-level accounts
        if event['columns'].get('type') != 'user':
            return False
        host_ip = event['columns'].get('host')
    elif 'last' in event['name']:
        host_ip = event['columns'].get('host')
    else:
        # A query we don't care about
        return False

    return _login_from_non_office_network(host_ip)


def title(event):
    msg = 'User [{}] has logged into production from a non-office network'
    user = event['columns'].get('user')
    username = event['columns'].get('username')

    if user is not None:
        return msg.format(user)

    if username is not None:
        return msg.format(username)

    return msg.format('<USER_NOT_FOUND>')
