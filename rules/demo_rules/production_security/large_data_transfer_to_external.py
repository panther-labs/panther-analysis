from ipaddress import ip_network

LARGE_TRANSFER_THRESHOLD = 104857600  # 100MB

# Panther UDM fields for VPC Flow logs
# source_ip: srcAddr
# destination_ip: dstAddr
# bytes: bytes (raw field)

def rule(event):
    # Only process if bytes field exists and is above threshold
    bytes_sent = event.get("bytes")
    if not isinstance(bytes_sent, int) or bytes_sent < LARGE_TRANSFER_THRESHOLD:
        return False

    # Get source and destination IPs
    source_ip = event.udm("source_ip")
    destination_ip = event.udm("destination_ip")
    if not source_ip or not destination_ip:
        return False

    # Only alert if source is internal and destination is external
    try:
        if not ip_network(source_ip).is_global and ip_network(destination_ip).is_global:
            return True
    except ValueError:
        # If IPs are malformed, skip
        return False

    return False

def title(event):
    return (
        f"Large Data Transfer from Internal to External IP: [{event.udm('source_ip')}] -> [{event.udm('destination_ip')}] for {event.get('bytes', '?')} bytes"
    )

def alert_context(event):
    return {
        "source_ip": event.udm("source_ip"),
        "destination_ip": event.udm("destination_ip"),
        "bytes": event.get("bytes"),
        "source_port": event.udm("source_port"),
        "destination_port": event.udm("destination_port"),
        "action": event.get("action"),
        "log_status": event.get("status") or event.get("log_status"),
    }

def runbook(event):
    return (
        "Investigate the source host for signs of compromise or unauthorized data transfer. "
        "Validate if the transfer was expected. Review the destination IP reputation and context. "
        "If suspicious, isolate the host and perform forensic analysis."
    ) 