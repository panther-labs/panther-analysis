from panther_base_helpers import deep_get

def rule(event):
    return True

def title(event):
    return (
        "Okta Login for "
        f"[{deep_get(event, 'actor', 'alternateId', default = '<email_not_found>')}]"
        " from unmanaged device."
    )
