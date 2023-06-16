import re

from global_filter_auth0 import filter_include_event
from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event
from panther_base_helpers import deep_get

org_re = re.compile(r"^/api/v2/organizations/[^/\s]+/invitations$")


def rule(event):
    if not any([filter_include_event(event), is_auth0_config_event(event)]):
        return False

    return invitation_type(event) is not None


def title(event):
    inv_type = invitation_type(event)
    if inv_type == "tenant":
        try:
            invitee = deep_get(event, "data", "details", "request", "body", "owners", default=[])[0]
        except IndexError:
            invitee = "<NO_INVITEE>"
    elif inv_type == "organization":
        invitee = deep_get(event, "data", "details", "request", "body", "invitee", "email")
    else:
        invitee = "<NO_INVITEE>"

    inviter = deep_get(
        event, "data", "details", "request", "auth", "user", "email", default="<NO_INVITER>"
    )
    source = deep_get(event, "p_source_label", default="<NO_PSOURCE>")
    return f"Auth0 User [{inviter}] invited [{invitee}] to {inv_type.title()} [{source}]]"


def invitation_type(event):
    path = deep_get(event, "data", "details", "request", "path", default="")

    if path == "/api/v2/tenants/invitations":
        return "tenant"
    if org_re.match(path):
        return "organization"

    return None


def alert_context(event):
    return auth0_alert_context(event)
