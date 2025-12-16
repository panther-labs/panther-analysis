def rule(event):
    """
    Detects when AWS WAF managed rule JavaDeserializationRCE_HEADER matches a request.

    This rule identifies potential Java deserialization RCE attempts through HTTP headers
    that match the JavaDeserializationRCE_HEADER managed rule from AWS WAF.
    """
    # Check if httpSourceName is ALB (optional - remove if you want all sources)
    if event.get("httpSourceName") != "ALB":
        return False

    # Check terminating rule match details
    terminating_matches = event.get("terminatingRuleMatchDetails", [])
    if terminating_matches and contains_java_deser_match(terminating_matches):
        return True

    # Check non-terminating matching rules
    non_terminating = event.get("nonTerminatingMatchingRules", [])
    if check_non_terminating_rules(non_terminating):
        return True

    # Check rule groups
    rule_groups = event.get("ruleGroupList", [])
    if check_rule_groups(rule_groups):
        return True

    return False


def contains_java_deser_match(match_details):
    """Check if match details contain JavaDeserializationRCE_HEADER"""
    for match in match_details:
        condition_type = match.get("conditionType", "")
        if "JavaDeserialization" in condition_type or "RCE" in condition_type:
            return True
    return False


def check_non_terminating_rules(rules):
    """Check non-terminating rules for JavaDeserializationRCE_HEADER match"""
    for rule in rules:
        rule_id = rule.get("ruleId", "")
        if "JavaDeserializationRCE_HEADER" in rule_id:
            return True

        # Check rule match details within non-terminating rules
        match_details = rule.get("ruleMatchDetails", [])
        if contains_java_deser_match(match_details):
            return True

    return False


def check_rule_groups(rule_groups):
    """Check rule groups for JavaDeserializationRCE_HEADER match"""
    for group in rule_groups:
        # Check terminating rule within group
        terminating_rule = group.get("terminatingRule", {})
        if terminating_rule:
            rule_id = terminating_rule.get("ruleId", "")
            if "JavaDeserializationRCE_HEADER" in rule_id:
                return True

            match_details = terminating_rule.get("ruleMatchDetails", [])
            if contains_java_deser_match(match_details):
                return True

        # Check non-terminating rules within group
        non_terminating = group.get("nonTerminatingMatchingRules", [])
        if check_non_terminating_rules(non_terminating):
            return True

    return False


def title(event):
    """Generate dynamic alert title"""
    client_ip = event.get("httpRequest", {}).get("clientIp", "unknown")
    action = event.get("action", "unknown")
    source = event.get("httpSourceName", "unknown")

    return f"AWS WAF JavaDeserializationRCE_HEADER Match - {action} from {client_ip} via {source}"


def alert_context(event):
    """Provide additional context for the alert"""
    http_request = event.get("httpRequest", {})

    context = {
        "client_ip": http_request.get("clientIp"),
        "country": http_request.get("country"),
        "http_method": http_request.get("httpMethod"),
        "uri": http_request.get("uri"),
        "user_agent": get_user_agent(http_request),
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
                "condition_type": match.get("conditionType"),
                "location": match.get("location"),
                "matched_strings": match.get("matchedData", [])
            }
            for match in terminating_matches
        ]

    return context


def get_user_agent(http_request):
    """Extract User-Agent from headers"""
    headers = http_request.get("headers", [])
    for header in headers:
        if header.get("name", "").lower() == "user-agent":
            return header.get("value")
    return None


def severity(event):
    """Dynamic severity based on action taken"""
    action = event.get("action", "")

    # If blocked, it's high severity (attempt was made)
    if action == "BLOCK":
        return "HIGH"

    # If allowed, it's critical (attack may have succeeded)
    if action == "ALLOW":
        return "CRITICAL"

    # If counted, it's medium (detected but no action)
    return "MEDIUM"
