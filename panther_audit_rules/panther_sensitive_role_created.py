import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get

PANTHER_ADMIN_PERMISSIONS = [
    "UserModify",
    "OrganizationAPITokenModify",
    "OrganizationAPITokenRead",
    "GeneralSettingsModify",
]

PANTHER_ROLE_ACTIONS = [
    event_type.USER_GROUP_CREATED,
    event_type.USER_GROUP_MODIFIED,
]

def rule(event):
    if event.udm(event_type) not in PANTHER_ROLE_ACTIONS:
        return False
    role_permissions= set(deep_get(event, 'action_params', 'input', 'permissions'))
    
    return (
        len(set(PANTHER_ADMIN_PERMISSIONS).intersection(role_permissions)) > 0
    )