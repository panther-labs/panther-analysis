import re

from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event

org_re = re.compile(r"^/api/v2/organizations/[^/\s]+/invitations$")


def rule(event):
    if not is_auth0_config_event(event):
        return False

    return invitation_type(event) is not None


def title(event):
    inv_type = invitation_type(event)
    if inv_type == "tenant":
        try:
            invitee = event.deep_get("data", "details", "request", "body", "owners", default=[])[0]
        except IndexError:
            invitee = "<NO_INVITEE>"
    elif inv_type == "organization":
        invitee = event.deep_get("data", "details", "request", "body", "invitee", "email")
    else:
        invitee = "<NO_INVITEE>"

    inviter = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_INVITER>"
    )
    source = event.get("p_source_label", "<NO_PSOURCE>")
    return f"Auth0 User [{inviter}] invited [{invitee}] to {inv_type} [{source}]]"


def invitation_type(event):
    path = event.deep_get("data", "details", "request", "path", default="")

    if path == "/api/v2/tenants/invitations":
        return "tenant"
    if org_re.match(path):
        return "organization"

    return None


def alert_context(event):
    return auth0_alert_context(event)
