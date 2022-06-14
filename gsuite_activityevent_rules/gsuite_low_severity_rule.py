from panther_base_helpers import deep_get


def rule(event):

    if deep_get(event, "id", "applicationName") != "rules":
        return False

    if not (
        deep_get(event, "parameters", "triggered_actions")
        and deep_get(event, "parameters", "severity") == "LOW"
    ):
        return False
    return True

def title(event):
    if deep_get(event, "parameters", "rule_name"):
        return "GSuite Low Severity Rule Triggered : " + deep_get(event, "parameters", "rule_name")
    
    return "GSuite Low Severity Rule Triggered"
