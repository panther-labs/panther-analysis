def rule(event):
    return event.get("action") == "two_factor_authentication.disabled"

def title(event):
    return (
      f"User [{event.get('actor_user', '<UNKNOWN_ACTOR_USER>')}] MFA Disabled"
    )
