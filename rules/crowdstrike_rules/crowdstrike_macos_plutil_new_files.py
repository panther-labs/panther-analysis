def rule(event):  # pylint: disable=unused-argument
    # The scheduled query returns only new plist files that haven't been modified before
    # Any result from the query should trigger an alert
    return True


def dedup(event):
    # Group alerts by device and plist file
    device_id = event.get("device_id", "<UNKNOWN_DEVICE>")
    plist_file = event.get("plist_file", "<UNKNOWN_FILE>")
    return f"{device_id}:{plist_file}"


def title(event):
    plist_file = event.get("plist_file", "<UNKNOWN_FILE>")
    return f"Crowdstrike: plutil modified new plist file: {plist_file}"


def alert_context(event):
    return {
        "device_id": event.get("device_id"),
        "plist_file": event.get("plist_file"),
        "detection_type": "Anomaly - New Modification Detected",
        "baseline_period": "30 days",
    }
