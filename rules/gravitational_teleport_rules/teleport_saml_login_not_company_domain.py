import re

from panther_config import config

TELEPORT_COMPANY_DOMAINS_REGEX = r"@(" + "|".join(config.TELEPORT_ORGANIZATION_DOMAINS) + r")$"


def rule(event):
    return (
        event.get("event") == "user.login"
        and event.get("success") is True
        and event.get("method") == "saml"
        and not re.search(TELEPORT_COMPANY_DOMAINS_REGEX, event.get("user"))
    )


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into "
        f"[{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] using "
        f"SAML, but not from a known company domain in "
        f"({','.join(config.TELEPORT_ORGANIZATION_DOMAINS)})"
    )
