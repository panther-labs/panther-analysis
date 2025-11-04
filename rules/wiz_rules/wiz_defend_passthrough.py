def rule(event):
    return event.get("severity") != "INFORMATIONAL"


def title(event):
    return f"[Wiz Alert]: " f"{event.get('tdrId')}"


def severity(event):
    return event.get("severity")


def dedup(event):
    # For lower-severity events, dedup based on specific source rule to reduce overall alert volume
    if event.get("severity") in ("INFO", "LOW"):
        dedup_str = str(event.get("tdrId"))
        if dedup_str:
            return dedup_str
    # If the severity is higher, or for some reason we couldn't generate a dedup string based on
    #   the source rule, then use the alert severity + the resource ID itself.
    return event.get("threatId") + "_" + event.get("severity", "<SEVERITY_NOT_FOUND>")


def description(event):
    return event.get("description")


def alert_context(event):
    return {
        "machine_id": event.deep_get("primaryResource", "externalId", default="<ID_NOT_FOUND>"),
        "machine_type": event.deep_get("primaryResource", "type", default="<TYPE_NOT_FOUND>"),
        "native_type": event.deep_get("primaryResource", "nativeType", default="<TYPE_NOT_FOUND>"),
        "machine_name": event.deep_get("primaryResource", "name", default="<NAME_NOT_FOUND>"),
        "mitre_attack_techniques": event.get("mitreTechniques"),
    }


def get_issue_url(event):
    if issue_id := event.get("id"):
        return f"https://app.wiz.io/issues#~(issue~'{issue_id})"
    return None  # Return None if there's no issue ID


def reference(event):
    return get_issue_url(event) or "DEFAULT"
