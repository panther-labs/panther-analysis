import panther_event_type_helpers as event_type
import re

successful_login = "Successful sign-in using .+ from .*"
admin_role_assigned = "Role changed from .+ to (Administrator|Account Owner)"

def get_event_type(event):
    # user item being audited
    if event.get("source_type") == "user":
        # check for login events
        if event.get("action") == "login":
            if bool(re.match(event.get("changes_description"), successful_login)):
                return event_type.SUCCESSFUL_LOGIN
        # check for admin assignment
        if event.get("action") == "update":
            if bool(re.match(event.get("changes_description"), admin_role_assigned, re.IGNORECASE)):
                return event_type.ADMIN_ROLE_ASSIGNED
    return None

def get_assigned_admin_role(event):
