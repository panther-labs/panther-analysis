from panther_base_helpers import deep_get


def rule(_):
    return True


def title(event):
    return (
        "Okta Login for "
        f"[{deep_get(event, 'actor', 'alternateId', default = '<email_not_found>')}]"
        " from unmanaged IP Address."
    )
