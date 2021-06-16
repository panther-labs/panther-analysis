def rule(event):
    return event.get("action") == "two_factor_authentication.disabled"

def title(event):
    return (
      f"User [{event.udm('actor_user')}] MFA Disabled"
    )
