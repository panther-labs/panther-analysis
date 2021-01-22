from fnmatch import fnmatch

import panther_event_type_helpers as event_type
from panther_gcp_helpers import get_binding_deltas

ADMIN_ROLES = {
    # Primitive Roles
    'roles/owner',
    # Predefined Roles
    'roles/*Admin'
}


def get_event_type(event):
    # currently, only tracking a handful of event types
    for delta in get_binding_deltas(event):
        if delta['action'] == 'ADD':
            if any([
                    fnmatch(delta.get('role', ''), admin_role_pattern)
                    for admin_role_pattern in ADMIN_ROLES
            ]):
                return event_type.ADMIN_ROLE_ASSIGNED

    return None
