from panther_base_helpers import deep_get
from panther_config import config


def rule(event):
    if deep_get(event, "id", "applicationName") != "user_accounts":
        return False

    if event.get("name") == "email_forwarding_out_of_domain":
        domain = deep_get(event, "parameters", "email_forwarding_destination_address").split("@")[
            -1
        ]
        if domain not in config.GSUITE_TRUSTED_FORWARDING_DESTINATION_DOMAINS:
            return True

    return False


def title(event):
    external_address = deep_get(event, "parameters", "email_forwarding_destination_address")
    user = deep_get(event, "actor", "email")

    return f"An email forwarding rule was created by {user} to {external_address}"
