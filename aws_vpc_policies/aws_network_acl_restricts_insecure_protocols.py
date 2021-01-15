from panther_base_helpers import IN_PCI_SCOPE
# This is a list of default ports for insecure protocols. As AWS Network ACLs and Security Groups
# are not application layer aware, this is the closest approximation that can be made to blocking
# insecure protocols. Application layer firewalls can provide stronger protections.
INSECURE_PORTS = {
    21,  # FTP command channel
    25,  # Unencrypted pop3 outgoing
    23,  # Telnet
    80,  # HTTP
    110,  # Unencrypted pop3 incoming
    587,  # Unencrypted pop3 outgoing
}


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    for entry in resource['Entries']:
        # Look for ingress rules from any IP.
        # This could be modified in the future to inspect the size
        # of the source network with the ipaddress.ip_network.num_addresses call.
        if entry['Egress']:
            continue

        # This indicates that all protocols are allowed, and the port range is ignored
        if entry['Protocol'] == '-1' or not entry['PortRange']:
            return False

        if any(entry['PortRange']['From'] <= port <= entry['PortRange']['To']
               for port in INSECURE_PORTS):
            return False
    return True
