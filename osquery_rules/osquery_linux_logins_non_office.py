import ipaddress

from panther_base_helpers import deep_get

# This is only an example network, but you can set it to whatever you'd like
OFFICE_NETWORKS = [
    ipaddress.ip_network("192.168.1.100/32"),
    ipaddress.ip_network("192.168.1.200/32"),
]


def _login_from_non_office_network(host):
    host_ipaddr = ipaddress.IPv4Address(host)

    non_office_logins = []
    for office_network in OFFICE_NETWORKS:
        non_office_logins.append(host_ipaddr in office_network)

    return not any(non_office_logins)


def rule(event):
    if event.get("action") != "added":
        return False

    if "logged_in_users" in event.get("name"):
        # Only pay attention to users and not system-level accounts
        if deep_get(event, "columns", "type") != "user":
            return False
    elif "last" in event.get("name"):
        pass
    else:
        # A query we don't care about
        return False

    host_ip = deep_get(event, "columns", "host")
    return _login_from_non_office_network(host_ip)


def title(event):
    user = (
        deep_get(event, "columns", "user", default=deep_get(event, "columns", "username"))
    )

    return (
        f"User [{user if user else '<UNKNOWN_USER>'}"
        f" has logged into production from a non-office network"
    )
