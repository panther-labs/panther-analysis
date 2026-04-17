ADMIN_KEYWORDS = {"owner", "admin"}


def rule(event):
    if event.get("type") != "role.assignment.created":
        return False

    assignment_id = event.deep_get("role_assignment_created", "id", default="")
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
    principal_id = event.deep_get("role_assignment_created", "principal_id", default="Unknown")
    email = event.deep_get("actor", "session", "user", "email", default="<UNKNOWN_USER>")
    return f"OpenAI Admin Role Assigned to {principal_id} by [{email}]"


def severity(event):
    assignment_id = event.deep_get("role_assignment_created", "id", default="")
    resource_type = event.deep_get("role_assignment_created", "resource_type", default="")

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
        "event_type": event.get("type", "<UNKNOWN_EVENT_TYPE>"),
        "event_id": event.get("id", "<UNKNOWN_EVENT_ID>"),
        "assignment_id": event.deep_get(
            "role_assignment_created", "id", default="<UNKNOWN_ASSIGNMENT_ID>"
        ),
        "principal_id": event.deep_get(
            "role_assignment_created", "principal_id", default="<UNKNOWN_PRINCIPAL_ID>"
        ),
        "principal_type": event.deep_get(
            "role_assignment_created", "principal_type", default="<UNKNOWN_PRINCIPAL_TYPE>"
        ),
        "resource_id": event.deep_get(
            "role_assignment_created", "resource_id", default="<UNKNOWN_RESOURCE_ID>"
        ),
        "resource_type": event.deep_get(
            "role_assignment_created", "resource_type", default="<UNKNOWN_RESOURCE_TYPE>"
        ),
        "actor_email": event.deep_get(
            "actor", "session", "user", "email", default="<UNKNOWN_ACTOR_EMAIL>"
        ),
        "actor_id": event.deep_get("actor", "session", "user", "id", default="<UNKNOWN_ACTOR_ID>"),
        "source_ip": event.deep_get(
            "actor", "session", "ip_address", default="<UNKNOWN_SOURCE_IP>"
        ),
        "user_agent": event.deep_get(
            "actor", "session", "user_agent", default="<UNKNOWN_USER_AGENT>"
        ),
    }
