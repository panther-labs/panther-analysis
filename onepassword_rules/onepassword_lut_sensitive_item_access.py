"""
This rule requires the use of the Lookup Table feature currently in Beta in Panther, 1Password
logs reference items by their UUID without human-friendly titles. The instructions to create a
lookup table to do this translation can be found at :

 https://docs.runpanther.io/guides/using-lookup-tables-1password-uuids

The steps detailed in that document are required for this rule to function as intended.
"""
from panther_base_helpers import deep_get


def rule(event):
    sensitive_item_watchlist = ["demo_item"]
    return (
        deep_get(event, "p_enrichment", "1Password Translation", "item_uuid", "title")
        in sensitive_item_watchlist
    )


def title(event):
    return f"A Sensitive 1Password Item was Accessed by user {deep_get(event, 'user', 'name')}"


def alert_context(event):
    context = {}
    context["user"] = deep_get(event, "user", "name")
    context["item_name"] = deep_get(
        event, "p_enrichment", "1Password Translation", "item_uuid", "title"
    )
    context["client"] = deep_get(event, "client", "app_name")
    context["ip_address"] = event.udm("source_ip")
    context["event_time"] = event.get("timestamp")

    return context
