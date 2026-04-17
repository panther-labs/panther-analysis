from panther_aws_helpers import (
    waf_alert_context,
    waf_get_matched_rule,
    waf_rule_group_matches,
    waf_severity,
)

RULE_GROUP = "AWSManagedRulesBotControlRuleSet"


def rule(event):
    return waf_rule_group_matches(event, RULE_GROUP)


def title(event):
    matched = waf_get_matched_rule(event, RULE_GROUP)
    client_ip = event.deep_get("httpRequest", "clientIp", default="<UNKNOWN_CLIENT_IP>")
    action = event.get("action", default="<UNKNOWN_ACTION>")
    source = event.get("httpSourceName", default="<UNKNOWN_SOURCE>")
    return f"AWS WAF Bot Control: {matched} - {action} from {client_ip} via {source}"


def alert_context(event):
    return waf_alert_context(event, RULE_GROUP)


def severity(event):
    return waf_severity(event)
