from global_filter_github import filter_include_event

ALLOWLIST_ACTIONS = [
    "ip_allow_list.enable",
    "ip_allow_list.disable",
    "ip_allow_list.enable_for_installed_apps",
    "ip_allow_list.disable_for_installed_apps",
    "ip_allow_list_entry.create",
    "ip_allow_list_entry.update",
    "ip_allow_list_entry.destroy",
]


def rule(event):
    if not filter_include_event(event):
        return False
    return (
        event.get("action").startswith("ip_allow_list") and event.get("action") in ALLOWLIST_ACTIONS
    )


def title(event):
    return f"GitHub Org IP Allow list modified by {event.get('actor')}."
