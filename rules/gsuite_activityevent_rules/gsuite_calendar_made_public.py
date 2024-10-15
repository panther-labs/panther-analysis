def rule(event):
    return (
        event.get("name") == "change_calendar_acls"
        and event.get("parameters", {}).get("grantee_email")
        == "__public_principal__@public.calendar.google.com"
    )


def title(event):
    return (
        f"GSuite calendar "
        f"[{event.deep_get('parameters', 'calendar_id', default='<NO_CALENDAR_ID>')}] made "
        f"{public_or_private(event)} by "
        f"[{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )


def severity(event):
    return "LOW" if public_or_private(event) == "private" else "MEDIUM"


def public_or_private(event):
    return "private" if event.deep_get("parameters", "access_level") == "none" else "public"
