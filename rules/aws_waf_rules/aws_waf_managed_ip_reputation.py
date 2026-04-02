import re

from panther_aws_helpers import waf_alert_context, waf_get_matched_rule, waf_rule_group_matches

STATIC_ASSET_PATTERN = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|woff2?|ttf|ico|map)$", re.IGNORECASE
)

RULE_GROUPS = [
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
]


def rule(event):
    if not waf_rule_group_matches(event, RULE_GROUPS):
        return False

    # Skip requests to static assets
    uri = event.deep_get("httpRequest", "uri", default="")

    if STATIC_ASSET_PATTERN.search(uri):
        return False

    return True


def title(event):
    matched = waf_get_matched_rule(event, RULE_GROUPS)
    client_ip = event.deep_get("httpRequest", "clientIp", default="<UNKNOWN_CLIENT_IP>")
    action = event.get("action", default="<UNKNOWN_ACTION>")
    source = event.get("httpSourceName", default="<UNKNOWN_SOURCE>")
    return f"AWS WAF IP Reputation: {matched} - {action} from {client_ip} via {source}"


def alert_context(event):
    return waf_alert_context(event, RULE_GROUPS)
