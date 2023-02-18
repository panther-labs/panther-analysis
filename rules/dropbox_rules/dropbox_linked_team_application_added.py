from panther_base_helpers import deep_get


def rule(event):
    return all(
        [
            deep_get(event, "event_type", "_tag", default="") == "app_link_team",
            deep_get(event, "event_type", "description", default="") == "Linked app for team",
        ]
    )


def severity(event):
    # Anything involving non-team members should be High
    if event.get("involve_non_team_member", False):
        return "High"
    return "Low"


def get_actor_type():
    return (
        # Admin who performed the action
        "admin",
        # Anonymous actor
        "anonymous",
        # Application that performed the action
        "app"
        # Action performed by Dropbox
        "dropbox",
        # Action performed by reseller
        "reseller",
        # User who performed the action
        "user",
    )


def title(event):
    # This will be one of the types returned by get_actor_type;
    # find the intersection and use that for the key
    actor_key = set(tuple(event.get("actor", {}).keys())).intersection(get_actor_type())
    if len(actor_key) == 1:
        display_name = deep_get(
            event, "actor", tuple(actor_key)[0], "display_name", default="<Unknown>"
        )
    # Explicitly use "<Unknown>" if we find any length of keys != 1
    else:
        display_name = "<Unknown>"
    return f"Dropbox Team Member Linked App by [{display_name}]"


def user_details(event):
    details = {}
    for actor_key, actor_value in event.get("actor", {}).items():
        if actor_key == "_tag":
            continue
        for user_key, user_info in actor_value.items():
            if user_key in ("_tag", "display_name"):
                continue
            details[user_key] = user_info
    return details


def alert_context(event):
    additional_user_details = user_details(event)
    return {
        "additional_user_details": additional_user_details,
        "app_display_name": deep_get(
            event, "details", "app_info", "display_name", default="<Unknown app display name>"
        ),
        "ip_address": deep_get(
            event, "origin", "geo_location", "ip_address", default="<Unknown IP address>"
        ),
        "request_id": deep_get(
            event, "origin", "access_method", "request_id", default="<Unknown request ID>"
        ),
    }
