def rule(event):
    return event.get("type") == "message.flagged"


def alert_context(event):
    flagged_rules = event.deep_walk("data", "flagged_rules", "name", default=["<UNKNOWN_NAMES>"])
    return {
        "flagged_rules": flagged_rules,
    }


def title(event):
    rule_count = len(event.deep_get("data", "flagged_rules", default=[]))
    return f"Sublime flagged email message that matched {rule_count} Sublime rules"
