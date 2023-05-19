from typing import Any

#
# Source mapping values from
# https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/
FIREWALL_SOURCE_MAPPING = {
    "unknown": "Unknown",
    "asn": "ASN",
    "country": "Country",
    "ip": "IP",
    "iprange": "IP Range",
    "securitylevel": "Security Level",
    "zonelockdown": "Zone Lockdown",
    "waf": "WAF",
    "firewallrules": "Firewall Rules",
    "uablock": "User Agent",
    "ratelimit": "Rate Limit",
    "bic": "Browser Integrity Check",
    "hot": "Hotlink Protection",
    "l7ddos": "L7 DDoS",
    "botfight": "Bot Fight (Classic)",
    "validation": "Invalid",
    "apishield": "API Shield",
    "botmanagement": "Bot Management",
    "dlp": "Data Loss Prevention",
    "firewallmanaged": "Firewall Managed Rules",
    "firewallcustom": "Firewall Custom Rulesets",
}


# Historical usage of map_source_to_name had detections
# passing in event.get('Source'), hence the Any input
def map_source_to_name(event: Any) -> str:
    if isinstance(event, str):
        return FIREWALL_SOURCE_MAPPING.get(event.lower(), event)
    return FIREWALL_SOURCE_MAPPING.get(
        event.get("Source", "").lower(), event.get("Source", "<NO_SOURCE>")
    )


def cloudflare_fw_alert_context(event: dict = None):
    keep_keys = [
        "Action",
        "ClientIP",
        "ClientRequestHost",
        "Datetime",
        "EdgeColoCode",
        "EdgeResponseStatus",
        "Kind",
        "RuleID",
        "Source",
    ]
    context_dict = {}
    for k in keep_keys:
        context_dict[k] = event.get(k, f"<{k}_NOT_IN_EVENT>")
    context_dict["pan_cf_source"] = map_source_to_name(event)
    return context_dict


def cloudflare_http_alert_context(event: dict = None):
    keep_keys = [
        "BotScore",
        "BotScoreSrc",
        "CacheCacheStatus",
        "CacheResponseStatus",
        "ClientIP",
        "ClientDeviceType",
        "ClientRequestHost",
        "ClientRequestMethod",
        "ClientRequestPath",
        "EdgeResponseStatus",
    ]
    context_dict = {}
    for k in keep_keys:
        if k in event:
            context_dict[k] = event.get(k, f"<{k}_NOT_IN_EVENT>")
    return context_dict
