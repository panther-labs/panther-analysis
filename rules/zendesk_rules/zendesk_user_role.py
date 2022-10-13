import panther_event_type_helpers as event_type
from panther_base_helpers import zendesk_get_roles


def rule(event):
    if event.get("source_type") == "user" and event.get("action") == "update":
        # admin roles have their own handling
        if event.udm("event_type") != event_type.ADMIN_ROLE_ASSIGNED:
            _, new_role = zendesk_get_roles(event)
            return bool(new_role)
    return False


def title(event):
    old_role, new_role = zendesk_get_roles(event)
    return (
        f"Actor user [{event.udm('actor_user')}] changed [{event.udm('user')}] role from "
        f"{old_role} to {new_role}"
    )
