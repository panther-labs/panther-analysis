import re
from fnmatch import fnmatch

from panther_base_helpers import m365_alert_context

email_regex = re.compile(r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")

ALLOWED_DOMAINS = ["mycompany.com", "alloweddomain.com"]

ALLOWED_USERS = ["exception@outsider.com"]

ALLOWED_PATHS = ["*/External/*", "External/*"]


def allowed_path(relative_url):
    for path in ALLOWED_PATHS:
        if fnmatch(relative_url, path):
            return True
    return False


def rule(event):
    if event.get("Operation", "") == "AnonymousLinkCreated":
        return not allowed_path(event.get("SourceRelativeUrl"))
    if event.get("Operation", "") == "AddedToSecureLink":
        if allowed_path(event.get("SourceRelativeUrl")):
            return False
        target = event.get("TargetUserOrGroupName", "")
        if target.lower() in ALLOWED_USERS:
            return False
        if re.fullmatch(email_regex, target):
            if target.split("@")[1].lower() not in ALLOWED_DOMAINS:
                return True
    return False


def title(event):
    return (
        f"Microsoft365: [{event.get('SourceRelativeUrl')}] " "has been shared with external users."
    )


def alert_context(event):
    return m365_alert_context(event)
