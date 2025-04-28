import panther_event_type_helpers as event_type

FAILED_LOGIN_ACTIONS = [
    event_type.USER_LOGIN_FAILED,
]

JACK_EMAIL = "jack@runpanther.io"  # Update this with Jack's actual email


def rule(event):
    # Return early if not a failed login event
    if event.udm("event_type") not in FAILED_LOGIN_ACTIONS:
        return False
    
    # Check if it's Jack's failed login
    if event.deep_get("actor", "attributes", "email") != JACK_EMAIL:
        return False
    
    # Return true since we found a failed login by Jack
    # Note: Thresholding is handled by Panther platform via the YAML config
    return True


def title(event):
    return f"Multiple failed login attempts detected for user {event.deep_get('actor', 'attributes', 'email')}"


def alert_context(event):
    return {
        "user_email": event.deep_get("actor", "attributes", "email"),
        "source_ip": event.udm("source_ip"),
        "user_agent": event.get("userAgent"),
        "timestamp": event.get("timestamp")
    } 