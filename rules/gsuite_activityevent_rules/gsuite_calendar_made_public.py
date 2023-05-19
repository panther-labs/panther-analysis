from panther_base_helpers import deep_get


def rule(event):
    return (
        event.get("name") == "change_calendar_acls"
        and event.get("parameters", {}).get("grantee_email")
        == "__public_principal__@public.calendar.google.com"
    )


def title(event):
    return (
        f"GSuite calendar "
        f"[{deep_get(event, 'parameters', 'calendar_id', default='<NO_CALENDAR_ID>')}] made "
        f"public by [{deep_get(event, 'actor', 'email', default='<NO_ACTOR_FOUND>')}]"
    )
