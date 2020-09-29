from fnmatch import fnmatch
from panther_gcp_helpers import get_binding_deltas

ADMIN_ROLES = {
    # Primitive Roles
    'roles/owner',
    # Predefined Roles
    'roles/*Admin'
}


def rule(event):
    for delta in get_binding_deltas(event):
        if delta['action'] != 'ADD':
            continue
        if any([
                fnmatch(delta.get('role'), admin_role_pattern)
                for admin_role_pattern in ADMIN_ROLES
        ]):
            return True
    return False


def title(event):
    return 'An admin role has been configured in GCP project {}'.format(
        event['resource'].get('labels', {}).get('project_id',
                                                '<PROJECT_NOT_FOUND>'))
