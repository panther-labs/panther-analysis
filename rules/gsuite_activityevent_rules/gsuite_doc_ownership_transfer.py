from panther_config import config

GSUITE_TRUSTED_OWNERSHIP_DOMAINS = {
    "@" + domain for domain in config.GSUITE_TRUSTED_OWNERSHIP_DOMAINS
}


def rule(event):
    if event.deep_get("id", "applicationName") != "admin":
        return False

    if bool(event.get("name") == "TRANSFER_DOCUMENT_OWNERSHIP"):
        new_owner = event.deep_get("parameters", "NEW_VALUE", default="<UNKNOWN USER>")
        return bool(new_owner) and not any(
            new_owner.endswith(x) for x in GSUITE_TRUSTED_OWNERSHIP_DOMAINS
        )
    return False
