"""
This rule detects unusual or unauthorized clients connecting to your 1Password account.
In order to get a baseline of what clients are being used in your environment run the following
query in Data Explorer:

select distinct client:app_name from panther_logs.public.onepassword_signinattempt

The client_allowlist variable is a collection of standard 1Password clients.
If this differs from your orginization's needs this rule can be edited to suit your environment
"""
from panther_base_helpers import deep_get


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
    ]

    return deep_get(event, "client", "app_name") not in client_allowlist


def title(event):
    return f"Unusual 1Password client - {deep_get(event, 'client', 'app_name')} detected"


def alert_context(event):
    context = {}
    context["user"] = deep_get(event, "target_user", "name", default="UNKNOWN_USER")
    context["user_email"] = event.udm("actor_user")
    context["ip_address"] = event.udm("source_ip")
    context["client"] = deep_get(event, "client", "app_name", default="UNKNOWN_CLIENT")
    context["OS"] = deep_get(event, "client", "os_name", default="UNKNOWN_OS")
    context["login_result"] = event.get("category")
    context["time_seen"] = event.get("timestamp")

    return context
