"""
This rule requires the use of the Lookup Table feature currently in Beta in Panther, 1Password
logs reference items by their UUID without human-friendly titles. The instructions to create a
lookup table to do this translation can be found at :

 https://docs.runpanther.io/guides/using-lookup-tables-1password-uuids

The steps detailed in that document are required for this rule to function as intended.
"""

# Add the human-readable names of 1Password items you want to monitor
SENSITIVE_ITEM_WATCHLIST = ["demo_item"]


def rule(event):
    return (
        event.deep_get("p_enrichment", "1Password Translation", "item_uuid", "title")
        in SENSITIVE_ITEM_WATCHLIST
    )


def title(event):
    return f"A Sensitive 1Password Item was Accessed by user {event.deep_get('user', 'name')}"


def alert_context(event):
    context = {
        "user": event.deep_get("user", "name"),
        "item_name": event.deep_get("p_enrichment", "1Password Translation", "item_uuid", "title"),
        "client": event.deep_get("client", "app_name"),
        "ip_address": event.udm("source_ip"),
        "event_time": event.get("timestamp"),
    }

    return context
