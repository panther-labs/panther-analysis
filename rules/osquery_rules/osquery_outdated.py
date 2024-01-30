from panther_base_helpers import deep_get

LATEST_VERSION = "5.10.2"


def rule(event):
    return (
        event.get("name") == "pack_it-compliance_osquery_info"
        and deep_get(event, "columns", "version") != LATEST_VERSION
        and event.get("action") == "added"
    )


def title(event):
    return f"Osquery Version {deep_get(event, 'columns', 'version')} is Outdated"
