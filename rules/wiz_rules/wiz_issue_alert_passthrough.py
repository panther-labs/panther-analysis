def rule(event):
    return (
        event.deep_get("issue", "status") == "OPEN"
        and event.deep_get("issue", "severity") != "INFORMATIONAL"
    )


def title(event):
    return f"[Wiz Alert]: " f"{event.deep_get('control', 'name', default='ALERT_NAME_NOT_FOUND')}"


def severity(event):
    return event.deep_get("issue", "severity")


def dedup(event):
    if event.deep_get("issue", "severity") in ("INFO", "LOW"):
        # If Wiz's severity is INFO or LOW, dedup on rule ID
        dedup_str = event.deep_get("control", "id", default="<NO_ID_FOUND>")
        if dedup_str:
            return dedup_str
    # If higher severity, dedup on the issue ID
    return (
        event.deep_get("issue", "id", default="<ISSUE_ID_NOT_FOUND>")
        + "_"
        + event.deep_get("issue", "severity", default="<SEVERITY_NOT_FOUND>")
    )


def description(event):
    return event.deep_get("control", "description", default="<DESCRIPTION_NOT_FOUND>")


def reference(event):
    return get_issue_url(event) or "DEFAULT"


def alert_context(event):
    return {
        "id": event.deep_get("resource", "id") or "<ID_NOT_FOUND>",
        "type": event.deep_get("resource", "type") or "<TYPE_NOT_FOUND>",
        "name": event.deep_get("resource", "name") or "<NAME_NOT_FOUND>",
    }


def get_issue_url(event):
    if issue_id := event.deep_get("issue", "id"):
        return f"https://app.wiz.io/issues#~(issue~'{issue_id})"
    return None  # Return None if there's no issue ID
