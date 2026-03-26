from panther_aws_helpers import (
    waf_alert_context,
    waf_get_matched_rule,
    waf_rule_group_matches,
    waf_severity,
)

RULE_GROUPS = [
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
]


def rule(event):
    return waf_rule_group_matches(event, RULE_GROUPS)


def title(event):
    matched = waf_get_matched_rule(event, RULE_GROUPS)
    client_ip = event.get("httpRequest", {}).get("clientIp", "unknown")
    action = event.get("action", "unknown")
    source = event.get("httpSourceName", "unknown")
    return f"AWS WAF IP Reputation: {matched} - {action} from {client_ip} via {source}"


def alert_context(event):
    return waf_alert_context(event, RULE_GROUPS)


def severity(event):
    return waf_severity(event)
