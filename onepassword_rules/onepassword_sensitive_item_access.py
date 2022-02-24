"""
This rule detects access to high sensitivity items in your 1Password account. 1Password references
these items by their UUID so the SENSITIVE_ITEM_WATCHLIST below allows for the mapping of UUID to
meaningful name.

There is an alternative method for creating this rule that uses Panther's lookup table feature,
(currently in beta). That rule can be found in the 1Password detection pack with the name
BETA - Sensitive 1Password Item Accessed (onepassword_lut_sensitive_item_access.py)
"""

from panther_base_helpers import deep_get

SENSITIVE_ITEM_WATCHLIST = {"ecd1d435c26440dc930ddfbbef201a11": "demo_item"}


def rule(event):
    return event.get("item_uuid") in SENSITIVE_ITEM_WATCHLIST.keys()


def title(event):
    return f"A Sensitive 1Password Item was Accessed by user {deep_get(event,'user', 'name')}"


def alert_context(event):
    context = {}
    context["user"] = deep_get(event, "user", "name")
    context["item_name"] = SENSITIVE_ITEM_WATCHLIST.get(event.get("item_uuid"))
    context["client"] = deep_get(event, "client", "app_name")
    context["ip_address"] = event.udm("source_ip")
    context["event_time"] = event.get("timestamp")

    return context
