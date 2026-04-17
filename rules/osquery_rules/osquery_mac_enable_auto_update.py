def rule(event):
    return (
        "SoftwareUpdate" in event.get("name", [])
        and event.get("action") == "added"
        and event.deep_get("columns", "domain") == "com.apple.SoftwareUpdate"
        and event.deep_get("columns", "key") == "AutomaticCheckEnabled"
        and
        # Send an alert if not set to "true"
        event.deep_get("columns", "value") == "false"
    )
