def rule(event):
    # The scheduled query returns only new plist files that haven't been modified before
    # Add additional filtering here if needed
    plist_file = event.get("plist_file", "")

    # Filter out empty, malformed, or invalid results
    if not plist_file:
        return False

    # Filter out whitespace-only strings
    if isinstance(plist_file, str) and not plist_file.strip():
        return False

    # Filter out placeholder/error values from query
    if plist_file == "<UNKNOWN_FILE>":
        return False

    # Any valid result from the query should trigger an alert
    return True


def dedup(event):
    # Group alerts by device and plist file
    device_id = event.get("device_id", "<UNKNOWN_DEVICE>")
    plist_file = event.get("plist_file", "<UNKNOWN_FILE>")
    return f"{device_id}:{plist_file}"


def title(event):
    plist_file = event.get("plist_file", "<UNKNOWN_FILE>")
    return f"Crowdstrike: plutil modified new plist file: {plist_file}"


def severity(event):
    plist_file = event.get("plist_file", "")

    # Critical: System-level persistence with elevated privileges
    if any(
        loc in plist_file for loc in ["/System/Library/LaunchDaemons/", "/Library/LaunchDaemons/"]
    ):
        return "HIGH"

    # High: System-level LaunchAgents or system directory modifications
    if "/Library/LaunchAgents/" in plist_file or "/System/" in plist_file:
        return "HIGH"

    # Default: Medium for all other novel modifications
    return "DEFAULT"


def alert_context(event):
    plist_file = event.get("plist_file", "<UNKNOWN_FILE>")

    # Determine risk indicators based on plist location
    risk_indicators = []
    if any(loc in plist_file for loc in ["/Library/LaunchAgents/", "/Library/LaunchDaemons/"]):
        risk_indicators.append("System-level persistence location")
    elif any(loc in plist_file for loc in ["LaunchAgents/", "LaunchDaemons/"]):
        risk_indicators.append("User-level persistence location")
    elif "/Applications/" in plist_file:
        risk_indicators.append("Application bundle modification (potential tampering)")
    elif "/System/" in plist_file:
        risk_indicators.append("System directory modification (elevated privileges)")

    return {
        "device_id": event.get("device_id", "<UNKNOWN_DEVICE>"),
        "plist_file": plist_file,
        "detection_type": "Anomaly - New Modification Detected",
        "baseline_period": "30 days",
        "risk_indicators": risk_indicators if risk_indicators else ["Non-standard plist location"],
    }
