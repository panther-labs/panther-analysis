from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "rules":
        return False

    if not(
        deep_get(event, "parameters", "triggered_actions")
        and deep_get(event, "parameters", "severity") == "MEDIUM"
    ):
        return False
    return True
