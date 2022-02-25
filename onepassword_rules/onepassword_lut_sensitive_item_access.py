"""
This rule requires the use of the Lookup Table feature currently in Beta in Panther, 1Password
logs reference items by their UUID without human-friendly titles. The instructions to create a
lookup table to do this translation can be found at :

 https://docs.runpanther.io/guides/using-lookup-tables-1password-uuids

The steps detailed in that document are required for this rule to function as intended.
"""
from panther_base_helpers import deep_get

# Add the human-readable names of 1Password items you want to monitor
SENSITIVE_ITEM_WATCHLIST = ["demo_item"]


def rule(event):
    return (
        deep_get(event, "p_enrichment", "1Password Translation", "item_uuid", "title")
        in SENSITIVE_ITEM_WATCHLIST
    )


def title(event):
    return f"A Sensitive 1Password Item was Accessed by user {deep_get(event, 'user', 'name')}"


def alert_context(event):
    context = {
        "user": deep_get(event, "user", "name"),
        "item_name": deep_get(event, "p_enrichment", "1Password Translation", "item_uuid", "title"),
        "client": deep_get(event, "client", "app_name"),
        "ip_address": event.udm("source_ip"),
        "event_time": event.get("timestamp"),
    }

    return context
