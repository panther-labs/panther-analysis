import ipaddress

# This is only an example network, but you can set it to whatever you'd like
OFFICE_NETWORKS = [ipaddress.ip_network('192.168.1.100/32')]


# TODO: Switch this to the `last` query and check the epoch to make sure they are new logins.
def rule(event):
    if event['action'] != 'added':
        return False

    if 'logged_in_users' not in event['name']:
        return False

    host_ip = event['columns'].get('host')
    if not host_ip:
        return False
    host_ipaddr = ipaddress.IPv4Address(host_ip)

    non_office_logins = []
    for office_network in OFFICE_NETWORKS:
        # Check the case where the OFFICE_NETWORK is a /32
        if office_network.num_addresses == 1:
            non_office_logins.append(
                office_network.network_address != host_ipaddr)
        # Check all possible hosts in the office subnet
        else:
            non_office_logins.append(host_ipaddr not in office_network.hosts())

    return any(non_office_logins)


def dedup(event):
    # Dedup by user to view lateral movement
    return event['columns'].get('user')


def title(event):
    return 'User [{}] has logged into production from a non-office network'.format(
        event['columns'].get('user', '<USER_NOT_FOUND>'))
