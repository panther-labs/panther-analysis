def rule(event):
    return event.get("action") == "org.disable_two_factor_requirement"


def title(event):
    return f"User [{event.udm('actor_user')}] disabled the {event.get('org','<UNKNOWN_ORG>')} 2FA requirement"
