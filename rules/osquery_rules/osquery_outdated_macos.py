SUPPORTED_VERSIONS = [
    "10.15.1",
    "10.15.2",
    "10.15.3",
]


def rule(event):
    return (
        event.get("name") == "pack_vuln-management_os_version"
        and event.deep_get("columns", "platform") == "darwin"
        and event.deep_get("columns", "version") not in SUPPORTED_VERSIONS
        and event.get("action") == "added"
    )
