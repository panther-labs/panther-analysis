import ipaddress

GLOBAL_IPV6 = ipaddress.IPv6Network("::/0")
# Choose an arbitrary sentinel value that isn't equivalent to the GLOBAL_IPV6 value.
IPV6_SENTINEL = ipaddress.IPv6Network("::1/128")


def policy(resource):
    # Enumerate the entries in the network ACL, in evaluation order.
    ingress_entries = sorted(
        (entry for entry in resource["Entries"] if not entry["Egress"]),
        key=lambda x: x["RuleNumber"],
    )
    for entry in ingress_entries:
        # Look for SSH ingress rules from wildcard IPs.
        if (
            entry.get("CidrBlock") == "0.0.0.0/0"
            # Handle non-standard representations like `"0::/0"`.
            or ipaddress.IPv6Network(entry.get("Ipv6CidrBlock") or IPV6_SENTINEL) == GLOBAL_IPV6
            == GLOBAL_IPV6
        ) and (
            not entry.get("PortRange")
            or entry["PortRange"]["From"] <= 22 <= entry["PortRange"]["To"]
        ):
            # If this is a deny rule, then the ACL has an explicit deny rule with a lower (more
            # important) precedence than any rule that would allow SSH from arbitrary IPs. If it's
            # an allow rule, then the opposite is true. Either way, this rule determines the
            # entire outcome of the policy evaluation.
            #
            # Another way to read this: pass the policy check if the SSH rule here is a deny.
            return entry["RuleAction"] == "deny"

    # Found no SSH ingress rules from wildcard IPs.
    return True
