"""
This rule detects unusual or unauthorized clients connecting to your 1Password account.
In order to get a baseline of what clients are being used in your environment run the following
query in Data Explorer:

select distinct client:app_name from panther_logs.public.onepassword_signinattempt

The client_allowlist variable is a collection of standard 1Password clients.
If this differs from your orginization's needs this rule can be edited to suit your environment
"""


def rule(event):
    client_allowlist = [
        "1Password CLI",
        "1Password for Web",
        "1Password for Mac",
        "1Password SCIM Bridge",  # Used for automated account provisioning
        "1Password for Windows",
        "1Password for iOS",
        "1Password Browser Extension",
        "1Password for Android",
        "1Password for Linux",
        "1Password SDK",
    ]

    return event.deep_get("client", "app_name") not in client_allowlist


def title(event):
    return f"Unusual 1Password client - {event.deep_get('client', 'app_name')} detected"


def alert_context(event):
    context = {}
    context["user"] = event.deep_get("target_user", "name", default="UNKNOWN_USER")
    context["user_email"] = event.udm("actor_user")
    context["ip_address"] = event.udm("source_ip")
    context["client"] = event.deep_get("client", "app_name", default="UNKNOWN_CLIENT")
    context["OS"] = event.deep_get("client", "os_name", default="UNKNOWN_OS")
    context["login_result"] = event.get("category")
    context["time_seen"] = event.get("timestamp")

    return context
