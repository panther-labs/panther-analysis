from ipaddress import ip_network

from panther_base_helpers import aws_rule_context
from panther_iocs import CRYPTO_MINING_PORTS

# List of allowed destination addresses
# with more commonly-used ports (e.g., 8080)
ALLOWED_DST_ADDRESSES = {}


def rule(event):
    # Only alert on traffic originating from a private address
    # and destined for a public address
    if any(
        [
            not ip_network(event.get("srcaddr", "0.0.0.0/0")).is_private,
            ip_network(event.get("dstaddr", "0.0.0.0/0")).is_private,
        ]
    ):
        return False

    return all(
        [
            event.get("dstport") in CRYPTO_MINING_PORTS,
            event.get("dstaddr") not in ALLOWED_DST_ADDRESSES,
        ]
    )


def alert_context(event):
    return aws_rule_context(event)
