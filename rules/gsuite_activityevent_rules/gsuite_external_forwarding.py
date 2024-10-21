from panther_config import config


def rule(event):
    if event.deep_get("id", "applicationName") not in ("user_accounts", "login"):
        return False

    if event.get("name") == "email_forwarding_out_of_domain":
        domain = event.deep_get("parameters", "email_forwarding_destination_address").split("@")[-1]
        if domain not in config.GSUITE_TRUSTED_FORWARDING_DESTINATION_DOMAINS:
            return True

    return False


def title(event):
    external_address = event.deep_get("parameters", "email_forwarding_destination_address")
    user = event.deep_get("actor", "email")

    return f"An email forwarding rule was created by {user} to {external_address}"
