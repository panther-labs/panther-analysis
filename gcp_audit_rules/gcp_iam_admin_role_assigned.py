from fnmatch import fnmatch

from panther_base_helpers import deep_get, get_binding_deltas

ADMIN_ROLES = {
    # Primitive Roles
    "roles/owner",
    # Predefined Roles
    "roles/*Admin",
}


def rule(event):
    for delta in get_binding_deltas(event):
        if delta.get("action") != "ADD":
            continue
        if any(
            (
                fnmatch(delta.get("role", ""), admin_role_pattern)
                for admin_role_pattern in ADMIN_ROLES
            )
        ):
            return True
    return False


def title(event):
    return (
        f"An admin role has been configured in GCP project "
        f"{deep_get(event, 'resource', 'labels', 'project_id', default='<UNKNOWN_PROJECT>')}"
    )
