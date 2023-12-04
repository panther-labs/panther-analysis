from panther_config import config


def rule(event):
    if event.get("operation", "") in ("Set-Mailbox", "New-InboxRule"):
        for param in event.get("parameters", []):
            if param.get("Name", "") in ("ForwardingSmtpAddress", "ForwardTo", "ForwardingAddress"):
                to_email = param.get("Value", "")
                if (
                    to_email.lower().replace("smtp:", "")
                    in config.MS_EXCHANGE_ALLOWED_FORWARDING_DESTINATION_EMAILS
                ):
                    return False
                for domain in config.MS_EXCHANGE_ALLOWED_FORWARDING_DESTINATION_DOMAINS:
                    if to_email.lower().replace("smtp:", "").endswith(domain):
                        return False
                return True
    return False


def title(event):
    to_email = "<no-recipient-found>"
    for param in event.get("parameters", []):
        if param.get("Name", "") in ("ForwardingSmtpAddress", "ForwardTo"):
            to_email = param.get("Value", "")
            break
    return (
        "Microsoft365: External Forwarding Created From "
        f"[{event.get('userid', '')}] to "
        f"[{to_email}]"
    )
