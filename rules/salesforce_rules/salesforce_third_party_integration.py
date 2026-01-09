def rule(event):
    # Alert on Connected App usage events
    # These track OAuth authorizations and third-party integrations
    return event.get("EVENT_TYPE") in [
        "ConnectedAppUsageEventStore",
        "ApiConnectedApp",
    ]


def title(event):
    # Create descriptive title with app and user details
    app_id = event.get("CONNECTED_APP_ID", "<UNKNOWN_APP>")
    app_name = event.get("CONNECTED_APP_NAME", app_id)
    user = event.get("USER_NAME", event.get("USER_ID", "<UNKNOWN_USER>"))
    connection_type = event.get("CONNECTION_TYPE", "<UNKNOWN_TYPE>")

    return f"Salesforce Connected App Access: {app_name} via {connection_type} - User: {user}"


def severity(event):
    # Map based on connection type and context
    connection_type = event.get("CONNECTION_TYPE", "").lower()
    app_name = event.get("CONNECTED_APP_NAME", "").lower()

    # OAuth refresh token grants are sensitive (persistent access)
    if "refresh" in connection_type:
        return "HIGH"

    # New app authorizations are notable
    if "authorization" in connection_type:
        return "MEDIUM"

    # Unknown or suspicious app names
    suspicious_keywords = ["test", "dev", "temp", "demo", "unknown"]
    if any(keyword in app_name for keyword in suspicious_keywords):
        return "MEDIUM"

    return "DEFAULT"


def dedup(event):
    # Deduplicate by app, user, and connection type
    app_id = event.get("CONNECTED_APP_ID", "unknown")
    user_id = event.get("USER_ID", "unknown")
    connection = event.get("CONNECTION_TYPE", "unknown")
    return f"SF_CONNECTED_APP_{app_id}_{user_id}_{connection}"


def alert_context(event):
    # Provide comprehensive context for investigation
    return {
        "Connected App ID": event.get("CONNECTED_APP_ID"),
        "Connected App Name": event.get("CONNECTED_APP_NAME"),
        "Connection Type": event.get("CONNECTION_TYPE"),
        "User ID": event.get("USER_ID"),
        "Username": event.get("USER_NAME"),
        "Source IP": event.get("SOURCE_IP"),
        "User Type": event.get("USER_TYPE"),
        "Request ID": event.get("REQUEST_ID"),
        "Organization ID": event.get("ORGANIZATION_ID"),
        "API Version": event.get("API_VERSION"),
        "OAuth Scopes": event.get("OAUTH_SCOPES"),
    }
