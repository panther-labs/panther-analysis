def rule(event):
    if event.deep_get("id", "applicationName") != "rules":
        return False

    if not event.deep_get("parameters", "triggered_actions"):
        return False
    return True


def title(event):
    rule_severity = event.deep_get("parameters", "severity")
    if event.deep_get("parameters", "rule_name"):
        return (
            "GSuite "
            + rule_severity
            + " Severity Rule Triggered: "
            + event.deep_get("parameters", "rule_name")
        )
    return "GSuite " + rule_severity + " Severity Rule Triggered"


def severity(event):
    return event.deep_get("parameters", "severity", default="INFO")
