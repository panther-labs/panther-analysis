ADMIN_USER_CHANGE_EVENTS = [
    "Created new admin",
    "Added SSO Admin",
    "Edited SSO Admin Record",
    "Created new support admin",
    "Edit admin record",
    "Deleted admin",
    "Enabled admin",
    "Disabled admin",
    "Unlocked admin",
    "Updated admin settings",
    "Deleted Netskope SSO admin",
]


def rule(event):
    if event.get("audit_log_event") in ADMIN_USER_CHANGE_EVENTS:
        return True
    return False


def title(event):
    user = event.get("user", "<USER_NOT_FOUND>")
    audit_log_event = event.get("audit_log_event", "<EVENT_NOT_FOUND>")
    return f"User [{user}] performed [{audit_log_event}]"


def severity(event):
    audit_log_event = event.get("audit_log_event", "no_data").lower()
    if "create" in audit_log_event or "add" in audit_log_event or "delete" in audit_log_event:
        return "CRITICAL"
    return "HIGH"
