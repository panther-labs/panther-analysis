def rule(event):
    # Cloudflare Rule IDs for CVE-2025-55182
    react2shell_rule_ids = [
        "33aa8a8a948b48b28d40450c5fb92fba",  # Managed Ruleset
        "2b5d06e34a814a889bee9a0699702280",  # Free Ruleset
    ]

    rule_id = event.get("RuleID", "")
    return rule_id in react2shell_rule_ids


def title(event):
    client_ip = event.get("ClientIP", "<UNKNOWN_IP>")
    return f"Cloudflare React2Shell (CVE-2025-55182) Exploit Detected from [{client_ip}]"


def alert_context(event):
    return {
        "vulnerability": "CVE-2025-55182 (React2Shell)",
        "action": event.get("Action"),
        "client_ip": event.get("ClientIP"),
        "client_country": event.get("ClientCountry"),
        "client_asn": event.get("ClientASN"),
        "client_ip_class": event.get("ClientIPClass"),
        "request_host": event.get("ClientRequestHost"),
        "request_method": event.get("ClientRequestMethod"),
        "request_path": event.get("ClientRequestPath"),
        "request_query": event.get("ClientRequestQuery"),
        "user_agent": event.get("ClientRequestUserAgent"),
        "edge_response_status": event.get("EdgeResponseStatus"),
        "rule_id": event.get("RuleID"),
        "rule_description": event.get("Description"),
        "source": event.get("Source"),
        "ray_id": event.get("RayID"),
        "edge_colo": event.get("EdgeColoCode"),
    }
