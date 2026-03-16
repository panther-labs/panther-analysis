from panther_crowdstrike_event_streams_helpers import audit_keys_dict, cs_alert_context

# List of priviledged roles.
# IMPORTANT: YOU MUST ADD ANY CUSTOM ADMIN ROLES YOURSELF
ADMIN_ROLES = {
    "billing_dashboard_admin",
    "falconhost_admin",
    "firewall_manager",
    "xdr_admin",  # NG SIEM Admin
    "remote_responder_three",  # Remote Responder Admin
}


def get_roles_assigned(event):
    """Returns a list of the roles assigned in this event."""
    # Extract the AuditKeyValues construct
    audit_keys = audit_keys_dict(event)
    # Return Roles
    return audit_keys.get("roles", "").split(",")


def rule(event):
    # Ignore non role-granting events
    if not all(
        [
            event.deep_get("event", "OperationName") == "grantUserRoles",
            event.deep_get("event", "Success"),
        ]
    ):
        return False

    # Raise alert if any of the admin roles were assigned
    roles_assigned = get_roles_assigned(event)
    return bool(ADMIN_ROLES & set(roles_assigned))


def title(event):
    audit_keys = audit_keys_dict(event)
    actor = audit_keys["actor_user"]
    target = audit_keys["target_name"]
    admin_roles = set(get_roles_assigned(event)) & ADMIN_ROLES
    return f"{actor} assigned admin roles to {target}: {', '.join(list(admin_roles))}"


def dedup(event):
    # The title includes the role names, but if the actor assigned more roles to the user, we
    #   dedup those alerts as well.
    audit_keys = audit_keys_dict(event)
    actor = audit_keys["actor_user"]
    target = audit_keys["target_name"]
    return f"{actor}-{target}"


def alert_context(event):
    context = cs_alert_context(event)
    actor = context.get("actor_user", "UNKNOWN_ACTOR")
    target = context.get("target_name", "UNKNOWN_TARGET")
    context["actor_target"] = f"{actor}-{target}"
    return context
