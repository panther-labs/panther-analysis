from panther_base_helpers import deep_get

ADMIN_ROLE_KEYWORDS = {
    "owner",
    "admin",
}


def get_role_name_from_assignment_id(assignment_id):
    if not assignment_id or not isinstance(assignment_id, str):
        return ""
    parts = assignment_id.split("_")
    if len(parts) > 1 and parts[0] == "role" and parts[1] == "assignment":
        role_part = parts[2] if len(parts) > 2 else ""
        if role_part.startswith("role-"):
            return role_part[5:]
    return ""


def is_admin_role(role_name):
    if not role_name:
        return False
    role_lower = role_name.lower()
    return any(keyword in role_lower for keyword in ADMIN_ROLE_KEYWORDS)


def rule(event):
    if event.get("type") != "role.assignment.created":
        return False

    assignment_id = deep_get(event, "role_assignment_created", "id", default="")
    role_name = get_role_name_from_assignment_id(assignment_id)
    return is_admin_role(role_name)


def title(event):
    assignment_id = deep_get(event, "role_assignment_created", "id", default="")
    role_name = get_role_name_from_assignment_id(assignment_id)
    principal_id = deep_get(event, "role_assignment_created", "principal_id", default="Unknown")
    principal_type = deep_get(
        event, "role_assignment_created", "principal_type", default="principal"
    )

    actor_email = deep_get(event, "actor", "session", "user", "email", default="Unknown User")

    return (
        f"Admin Role Assignment: {role_name} granted to "
        f"{principal_type} {principal_id} by {actor_email}"
    )


def dedup(event):
    principal_id = deep_get(event, "role_assignment_created", "principal_id", default="unknown")
    assignment_id = deep_get(event, "role_assignment_created", "id", default="unknown")
    return f"role.assignment.created:{principal_id}:{assignment_id}"


def severity(event):
    assignment_id = deep_get(event, "role_assignment_created", "id", default="")
    role_name = get_role_name_from_assignment_id(assignment_id)
    resource_type = deep_get(event, "role_assignment_created", "resource_type", default="")

    if not role_name:
        return "DEFAULT"

    role_lower = role_name.lower()

    if "organization" in resource_type.lower() and "owner" in role_lower:
        return "CRITICAL"

    if is_admin_role(role_name):
        return "HIGH"

    return "DEFAULT"


def alert_context(event):
    context = {
        "event_type": event.get("type"),
        "event_id": event.get("id"),
        "effective_at": event.get("effective_at"),
    }

    assignment = deep_get(event, "role_assignment_created", default={})
    if assignment:
        assignment_id = assignment.get("id", "")
        context.update(
            {
                "assignment_id": assignment_id,
                "role_name": get_role_name_from_assignment_id(assignment_id),
                "principal_id": assignment.get("principal_id"),
                "principal_type": assignment.get("principal_type"),
                "resource_id": assignment.get("resource_id"),
                "resource_type": assignment.get("resource_type"),
            }
        )

    actor = event.get("actor", {})
    actor_type = actor.get("type", "")

    if actor_type == "session":
        context.update(
            {
                "actor_type": "user_session",
                "user_email": deep_get(actor, "session", "user", "email"),
                "user_id": deep_get(actor, "session", "user", "id"),
                "source_ip": deep_get(actor, "session", "ip_address"),
                "user_agent": deep_get(actor, "session", "user_agent"),
                "ja3_fingerprint": deep_get(actor, "session", "ja3"),
                "ja4_fingerprint": deep_get(actor, "session", "ja4"),
            }
        )

        ip_details = deep_get(actor, "session", "ip_address_details", default={})
        if ip_details:
            context.update(
                {
                    "country": ip_details.get("country"),
                    "city": ip_details.get("city"),
                    "region": ip_details.get("region"),
                }
            )

    return context
