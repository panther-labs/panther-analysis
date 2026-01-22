def rule(event):
    # Alert on OAuth-related events that may indicate credential abuse
    event_type = event.get("EVENT_TYPE", "")

    # Monitor OAuth token usage and authentication events
    oauth_events = [
        "OAuthTokenRevoked",
        "OAuthTokenRefreshFailed",
        "ApiTotalUsage",
        "ApiConnectedApp",
    ]

    return event_type in oauth_events or "oauth" in str(event_type).lower()


def title(event):
    # Create descriptive title based on event type
    event_type = event.get("EVENT_TYPE", "<UNKNOWN_EVENT>")
    user = event.get("USER_NAME", event.get("USER_ID", "<UNKNOWN_USER>"))
    app_name = event.get("CONNECTED_APP_NAME", event.get("CLIENT_NAME", "<UNKNOWN_APP>"))

    # Special handling for different event types
    if "Revoked" in event_type:
        return f"Salesforce OAuth Token Revoked: {app_name} - User: {user}"
    if "Failed" in event_type:
        return f"Salesforce OAuth Token Refresh Failed: {app_name} - User: {user}"

    return f"Salesforce OAuth Activity: {event_type} - {app_name} - User: {user}"


def severity(event):
    # Map based on event type and context
    event_type = event.get("EVENT_TYPE", "")
    status = str(event.get("STATUS", "")).lower()

    # Token revocation may indicate compromise
    if "Revoked" in event_type:
        return "HIGH"

    # Failed token operations are suspicious
    if "Failed" in event_type or "fail" in status:
        return "MEDIUM"

    # Excessive API usage may indicate abuse
    api_calls = event.get("API_TOTAL_COUNT", 0)
    # Ensure api_calls is numeric
    api_calls = api_calls if isinstance(api_calls, (int, float)) else 0
    if api_calls > 10000:
        return "HIGH"
    if api_calls > 5000:
        return "MEDIUM"

    return "DEFAULT"


def dedup(event):
    # Deduplicate by event type, user, and app
    event_type = event.get("EVENT_TYPE", "unknown")
    user_id = event.get("USER_ID", "unknown")
    app_id = event.get("CONNECTED_APP_ID", event.get("CLIENT_ID", "unknown"))
    return f"SF_OAUTH_ABUSE_{event_type}_{user_id}_{app_id}"


def alert_context(event):
    # Provide comprehensive context for investigation
    return {
        "Event Type": event.get("EVENT_TYPE"),
        "User ID": event.get("USER_ID"),
        "Username": event.get("USER_NAME"),
        "Connected App ID": event.get("CONNECTED_APP_ID"),
        "Connected App Name": event.get("CONNECTED_APP_NAME"),
        "Client ID": event.get("CLIENT_ID"),
        "Client Name": event.get("CLIENT_NAME"),
        "Source IP": event.get("SOURCE_IP"),
        "Status": event.get("STATUS"),
        "API Total Count": event.get("API_TOTAL_COUNT"),
        "Request ID": event.get("REQUEST_ID"),
        "Organization ID": event.get("ORGANIZATION_ID"),
        "Session Key": event.get("SESSION_KEY"),
    }
