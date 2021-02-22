from panther_base_helpers import deep_get


def rule(event):
    return (
        "SoftwareUpdate" in event.get("name", [])
        and event.get("action") == "added"
        and deep_get(event, "columns", "domain") == "com.apple.SoftwareUpdate"
        and deep_get(event, "columns", "key") == "AutomaticCheckEnabled"
        and
        # Send an alert if not set to "true"
        deep_get(event, "columns", "value") == "false"
    )
