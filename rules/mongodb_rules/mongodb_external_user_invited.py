import json
from unittest.mock import MagicMock

from panther_base_helpers import deep_get

# Set domains allowed to join the organization ie. company.com
ALLOWED_DOMAINS = []


def rule(event):
    global ALLOWED_DOMAINS  # pylint: disable=global-statement
    if isinstance(ALLOWED_DOMAINS, MagicMock):
        ALLOWED_DOMAINS = json.loads(ALLOWED_DOMAINS())  # pylint: disable=not-callable
    if deep_get(event, "eventTypeName", default="") == "INVITED_TO_ORG":
        target_user = deep_get(event, "targetUsername", default="")
        target_domain = target_user.split("@")[-1]
        return target_domain not in ALLOWED_DOMAINS
    return False


def title(event):
    actor = event.get("username", "<USER_NOT_FOUND>")
    target = event.get("targetUsername", "<USER_NOT_FOUND>")
    org_id = event.get("orgId", "<ORG_NOT_FOUND>")
    return f"MongoDB Atlas: [{actor}] invited external user [{target}] to the org [{org_id}]"


def alert_context(event):
    return {
        "username": event.get("username", "<USER_NOT_FOUND>"),
        "target_username": event.get("targetUsername", "<USER_NOT_FOUND>"),
        "org_id": event.get("orgId", "<ORG_NOT_FOUND>"),
    }
