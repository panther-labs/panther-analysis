def rule(event):
    return event.deep_get("workflow", "changed_by") == "ALERT_CREATION"


def title(event):
    return (
        f"{event.get('attack_tactic', 'CB')}: "
        f"{event.get('device_username', '<no-user-found>')} on "
        f"{event.get('device_name', '<no-device-found>')}: "
        f"{event.get('reason', '<no-reason-found>')}"
    )


def description(event):
    return event.get("reason", "<no-reason-found>")


def severity(event):
    sev = event.get("severity")
    if sev >= 9:
        return "CRITICAL"
    if sev >= 7:
        return "HIGH"
    if sev >= 5:
        return "MEDIUM"
    if sev >= 3:
        return "LOW"
    return "INFO"


def reference(event):
    return event.get("alert_url")


def dedup(event):
    return event.get("id")
