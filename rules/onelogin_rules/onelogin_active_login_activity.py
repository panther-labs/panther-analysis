from panther_base_helpers import is_ip_in_network

# Safelist for IP Subnets to ignore in this ruleset
# Each entry in the list should be in CIDR notation
# This should include any source ip addresses
# that are shared among users such as:
# proxy servers, the public corporate ip space,
# scanner ips etc
SHARED_IP_SPACE = [
    "192.168.0.0/16",
]


def rule(event):
    # Pre-filter: event_type_id = 5 is login events.
    if (
        str(event.get("event_type_id")) != "5"
        or not event.get("ipaddr")
        or not event.get("user_id")
    ):
        return False
    # We expect to see multiple user logins from these shared, common ip addresses
    if is_ip_in_network(event.get("ipaddr"), SHARED_IP_SPACE):
        return False
    return True


def unique(event):
    return str(event.get("user_id", ""))


def dedup(event):
    return event.get("ipaddr", "<UNKNOWN_IP>")


def title(event):
    return (
        f"Unusual logins in OneLogin for multiple users from ip "
        f"[{event.get('ipaddr', '<UNKNOWN_IP>')}]"
    )
