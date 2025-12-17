from panther_cloudflare_helpers import cloudflare_fw_alert_context

# Cloudflare Rule IDs for CVE-2025-55182
REACT2SHELL_RULE_IDS = [
    "33aa8a8a948b48b28d40450c5fb92fba",  # Managed Ruleset
    "2b5d06e34a814a889bee9a0699702280",  # Free Ruleset
]


def rule(event):
    rule_id = event.get("RuleID", "")
    return rule_id in REACT2SHELL_RULE_IDS


def title(event):
    client_ip = event.get("ClientIP", "<UNKNOWN_IP>")
    return f"Cloudflare React2Shell (CVE-2025-55182) Exploit Detected from [{client_ip}]"


def alert_context(event):
    return cloudflare_fw_alert_context(event)
