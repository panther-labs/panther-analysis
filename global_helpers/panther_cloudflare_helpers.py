FIREWALL_SOURCE_MAPPING = {
    "unknown": "Unknown",
    "asn": "ASN",
    "country": "Country",
    "ip": "IP",
    "ipRange": "IP Range",
    "securityLevel": "Security Level",
    "zoneLockdown": "Zone Lockdown",
    "waf": "WAF",
    "firewallRules": "Firewall Rules",
    "uaBlock": "User Agent",
    "rateLimit": "Rate Limit",
    "bic": "Browser Integrity Check",
    "hot": "Hotlink Protection",
    "l7ddos": "L7 DDoS",
    "validation": "Invalid",
    "botFight": "Bot Fight (Classic)",
    "botManagement": "Bot Management",
    "dlp": "Data Loss Prevention",
    "firewallManaged": "Firewall Managed Rules",
    "firewallCustom": "Firewall Custom Rulesets"
}


def map_source_to_name(source):
    if source in FIREWALL_SOURCE_MAPPING:
        return FIREWALL_SOURCE_MAPPING[source]
    return source
