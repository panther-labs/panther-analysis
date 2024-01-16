import re

from panther_config import config

TELEPORT_ORGANIZATION_DOMAINS_REGEX = r"@(" + "|".join(config.TELEPORT_ORGANIZATION_DOMAINS) + r")$"


def rule(event):
    return bool(
        event.get("event") == "user.login"
        and event.get("success") is True
        and bool(re.search(TELEPORT_ORGANIZATION_DOMAINS_REGEX, event.get("user")))
        and event.get("method") != "saml"
    )


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into "
        f"[{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] without "
        f"using SAML"
    )
