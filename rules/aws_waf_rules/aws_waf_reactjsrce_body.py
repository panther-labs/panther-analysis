RULE_ID = "ReactJSRCE_BODY"


def rule(event):
    # Direct check of terminating rule ID
    if RULE_ID in event.get("terminatingRuleId", ""):
        return True

    # Check non-terminating rules
    for matching_rule in event.get("nonTerminatingMatchingRules", []) or []:
        if RULE_ID in matching_rule.get("ruleId", ""):
            return True

    # Check rule groups
    for group in event.get("ruleGroupList", []) or []:
        terminating = group.get("terminatingRule") or {}
        if RULE_ID in terminating.get("ruleId", ""):
            return True

        for matching_rule in group.get("nonTerminatingMatchingRules", []) or []:
            if RULE_ID in matching_rule.get("ruleId", ""):
                return True

    return False


def title(event):
    client_ip = event.get("httpRequest", {}).get("clientIp", "unknown")
    action = event.get("action", "unknown")
    source = event.get("httpSourceName", "unknown")
    return f"AWS WAF {RULE_ID} Match - {action} from {client_ip} via {source}"


def alert_context(event):
    http_request = event.get("httpRequest", {})
    headers = http_request.get("headers", [])
    user_agent = next(
        (h.get("value") for h in headers if h.get("name", "").lower() == "user-agent"), None
    )

    context = {
        "client_ip": http_request.get("clientIp"),
        "country": http_request.get("country"),
        "http_method": http_request.get("httpMethod"),
        "uri": http_request.get("uri"),
        "user_agent": user_agent,
        "action": event.get("action"),
        "source": event.get("httpSourceName"),
        "source_id": event.get("httpSourceId"),
        "terminating_rule_id": event.get("terminatingRuleId"),
        "terminating_rule_type": event.get("terminatingRuleType"),
    }

    # Add matched data if available
    terminating_matches = event.get("terminatingRuleMatchDetails", [])
    if terminating_matches:
        context["matched_data"] = [
            {
                "condition_type": m.get("conditionType"),
                "location": m.get("location"),
                "matched_strings": m.get("matchedData", []),
            }
            for m in terminating_matches
        ]

    return context


def severity(event):
    action = event.get("action", "")
    if action == "ALLOW":
        return "CRITICAL"
    if action == "BLOCK":
        return "HIGH"
    if action == "COUNT":
        return "MEDIUM"
    return "DEFAULT"
