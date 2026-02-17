from ipaddress import ip_address

from panther_kubernetes_helpers import k8s_alert_context


def rule(event):
    response_status = event.udm("responseStatus") or {}
    source_ips = event.udm("sourceIPs") or []

    # Check for 403 response (HTTP) or 7 (gRPC PERMISSION_DENIED)
    status_code = response_status.get("code")
    if status_code not in (403, 7):
        return False
    if not source_ips:
        return False

    try:
        source_ip = source_ips[0]
        ip_obj = ip_address(source_ip)
        # alert on public IPs
        if ip_obj.is_global:
            return True
    except (ValueError, IndexError):
        return False

    return False


def title(event):
    source_ips = event.udm("sourceIPs") or []
    source_ip = source_ips[0] if source_ips else "<UNKNOWN_IP>"

    return f"Multiple 403 responses from public IP [{source_ip}]"


def dedup(event):
    source_ips = event.udm("sourceIPs") or []
    source_ip = source_ips[0] if source_ips else "<UNKNOWN_IP>"
    return f"k8s_403_{source_ip}"


def alert_context(event):
    return k8s_alert_context(event)
