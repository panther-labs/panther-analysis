from panther_cloudflare_helpers import map_source_to_name


def rule(event):
    if event.get("Action") != "block":
        return False
    return True


def title(event):
    return (
        f"High Volume Events Blocked - "
        f"{map_source_to_name(event.get('Source'))}: {event.get('ClientIP')}"
    )


def dedup(event):
    return f"{event.get('ClientIP')}:{event.get('Source')}"
