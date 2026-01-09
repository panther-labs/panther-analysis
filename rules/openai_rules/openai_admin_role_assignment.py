from panther_base_helpers import deep_get

ADMIN_KEYWORDS = {"owner", "admin"}


def rule(event):
    if event.get("type") != "role.assignment.created":
        return False

    assignment_id = deep_get(event, "role_assignment_created", "id", default="")
    if not assignment_id:
        return False

    # Parse: role_assignment_role-api-organization-owner__..._user-123
    # Extract: api-organization-owner
    parts = assignment_id.split("_")
    if len(parts) > 2 and parts[0] == "role" and parts[1] == "assignment":
        role_part = parts[2]
        if role_part.startswith("role-"):
            role_name = role_part[5:].lower()
            return any(keyword in role_name for keyword in ADMIN_KEYWORDS)

    return False


def title(event):
    principal_id = deep_get(event, "role_assignment_created", "principal_id", default="Unknown")
    email = event.deep_get("actor", "session", "user", "email", default="<UNKNOWN_USER>")
    return f"OpenAI Admin Role Assigned to {principal_id} by [{email}]"


def severity(event):
    assignment_id = deep_get(event, "role_assignment_created", "id", default="")
    resource_type = deep_get(event, "role_assignment_created", "resource_type", default="")

    if not assignment_id:
        return "DEFAULT"

    assignment_lower = assignment_id.lower()

    if "organization" in resource_type.lower() and "owner" in assignment_lower:
        return "CRITICAL"
    if "admin" in assignment_lower:
        return "HIGH"

    return "DEFAULT"


def alert_context(event):
    return {
        "event_type": event.get("type"),
        "event_id": event.get("id"),
        "assignment_id": deep_get(event, "role_assignment_created", "id"),
        "principal_id": deep_get(event, "role_assignment_created", "principal_id"),
        "principal_type": deep_get(event, "role_assignment_created", "principal_type"),
        "resource_id": deep_get(event, "role_assignment_created", "resource_id"),
        "resource_type": deep_get(event, "role_assignment_created", "resource_type"),
        "actor_email": deep_get(event, "actor", "session", "user", "email"),
        "actor_id": deep_get(event, "actor", "session", "user", "id"),
        "source_ip": deep_get(event, "actor", "session", "ip_address"),
        "user_agent": deep_get(event, "actor", "session", "user_agent"),
    }
