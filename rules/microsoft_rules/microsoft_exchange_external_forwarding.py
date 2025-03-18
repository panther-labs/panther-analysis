from panther_msft_helpers import is_external_address, m365_alert_context

FORWARDING_PARAMETERS = {
    "ForwardingSmtpAddress",
    "ForwardTo",
    "ForwardingAddress",
    "RedirectTo",
    "ForwardAsAttachmentTo",
}

SUSPICIOUS_PATTERNS = {
    "DeliverToMailboxAndForward": "False",  # Only forward, don't keep copy
    "DeleteMessage": "True",  # Delete after forwarding
    "StopProcessingRules": "True",  # Stop processing other rules
}


def rule(event):
    """Alert on suspicious or external email forwarding configurations."""
    # Skip non-forwarding related operations
    if event.get("operation") not in ("Set-Mailbox", "New-InboxRule"):
        return False

    # Get organization domains from userid and organizationname
    onmicrosoft_domain = event.get("organizationname", "").lower()
    userid = event.get("userid", "").lower()
    try:
        primary_domain = userid.split("@")[1]
    except (IndexError, AttributeError):
        primary_domain = onmicrosoft_domain if onmicrosoft_domain else None

    if not primary_domain:
        return True  # Alert if we can't determine organization

    # Check each parameter
    for param in event.get("parameters", []):
        param_name = param.get("Name", "")
        param_value = param.get("Value", "")

        # Check for suspicious patterns
        if param_name in SUSPICIOUS_PATTERNS and param_value == SUSPICIOUS_PATTERNS[param_name]:
            return True

        # Check for external forwarding
        if param_name in FORWARDING_PARAMETERS and param_value:
            if is_external_address(param_value, primary_domain, onmicrosoft_domain):
                return True

    return False


def title(event):
    parameters = event.get("parameters", [])
    forwarding_addresses = []
    suspicious_configs = []

    for param in parameters:
        param_name = param.get("Name", "")
        param_value = param.get("Value", "")

        if param_name in FORWARDING_PARAMETERS and param_value:
            # Handle smtp: prefix
            if param_value.lower().startswith("smtp:"):
                param_value = param_value[5:]
            # Handle multiple addresses
            addresses = param_value.split(";")
            forwarding_addresses.extend(addr.strip() for addr in addresses if addr.strip())
        if param_name in SUSPICIOUS_PATTERNS and param_value == SUSPICIOUS_PATTERNS[param_name]:
            suspicious_configs.append(f"{param_name}={param_value}")

    to_emails = ", ".join(forwarding_addresses) if forwarding_addresses else "<no-recipient-found>"
    suspicious_str = f" [Suspicious: {', '.join(suspicious_configs)}]" if suspicious_configs else ""

    return (
        f"Microsoft365: External Forwarding Created From [{event.get('userid', '')}] "
        f"to [{to_emails}]{suspicious_str}"
    )


def alert_context(event):
    return m365_alert_context(event)
