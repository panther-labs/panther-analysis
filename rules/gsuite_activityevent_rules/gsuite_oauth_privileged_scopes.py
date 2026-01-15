from panther_gsuite_helpers import gsuite_parameter_lookup

PRIVILEGED_SCOPES = ["admin.directory.user", "ediscovery", "drive", "cloud_search.query"]


def rule(event):
    scopes = event.deep_get("parameters", "scope", default=[])
    app_name = event.deep_get("id", "applicationName", default="")
    event_name = event.get("name")

    # Handle both list and string formats
    if scopes and isinstance(scopes, str):
        scopes = [scopes]

    return all(
        [
            app_name == "token",
            event_name == "authorize",
            any(
                scope_url.split("/")[-1].lower() in [ps.lower() for ps in PRIVILEGED_SCOPES]
                for scope_url in scopes
            ),
        ]
    )


def title(event):
    actor = event.deep_get("actor", "email", default="<UNKNOWN_USER>")
    app_name = event.deep_get("parameters", "app_name", default="<UNKNOWN_APP>")

    return (
        f"Google Workspace: User [{actor}] authorized OAuth app [{app_name}] with privileged scopes"
    )


def alert_context(event):
    parameters = event.get("parameters", {})

    return {
        "actor": event.deep_get("actor", "email", default=""),
        "app_name": gsuite_parameter_lookup(parameters, "app_name"),
        "client_id": gsuite_parameter_lookup(parameters, "client_id"),
        "client_type": gsuite_parameter_lookup(parameters, "client_type"),
        "scopes": gsuite_parameter_lookup(parameters, "scope"),
        "scope_data": gsuite_parameter_lookup(parameters, "scope_data"),
        "event_type": event.get("name"),
        "ip_address": event.get("ipAddress"),
    }
