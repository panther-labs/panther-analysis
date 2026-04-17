LATEST_VERSION = "5.10.2"


def rule(event):
    return (
        event.get("name") == "pack_it-compliance_osquery_info"
        and event.deep_get("columns", "version") != LATEST_VERSION
        and event.get("action") == "added"
    )


def title(event):
    return f"Osquery Version {event.deep_get('columns', 'version')} is Outdated"
