FINE_GRAINED_ACTION = "personal_access_token.access_granted"

LEGACY_ACTION = "org_credential_authorization.grant"

OAUTH_TYPE = "Personal Access Token"


def rule(event):
    does_action_match: bool = event.get("action") == FINE_GRAINED_ACTION
    does_legacy_action_match: bool = event.get("action") == LEGACY_ACTION
    does_oauth_type_match: bool = event.get("oauth_credential_type") == OAUTH_TYPE

    if does_action_match or (does_legacy_action_match and does_oauth_type_match):
        return True
    return False


def title(event):
    return (
        f"User [{event.deep_get('actor')}]"
        f"performed a Personal Access Token (PAT) "
        f"for an action in OMGWINNING."
    )
