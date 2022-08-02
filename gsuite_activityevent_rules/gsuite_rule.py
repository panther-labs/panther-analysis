from panther_base_helpers import deep_get

def rule(event):
    if deep_get(event, "id", "applicationName") != "rules":
        return False

    if not (
        deep_get(event, "parameters", "triggered_actions")
    ):
        return False
    return True

def title(event):
    rule_severity = deep_get(event, "parameters", "severity")
    if deep_get(event, "parameters", "rule_name"):
        return "GSuite " + rule_severity + " Severity Rule Triggered: " \
            + deep_get(event, "parameters", "rule_name")
    return "GSuite " + rule_severity + " Severity Rule Triggered"

def severity(event):
    return deep_get(event, "parameters", "severity")
