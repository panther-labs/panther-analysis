from panther_base_helpers import deep_get


def rule(_):
    return True


def title(event):
    return (
        "1Password Login for "
        f"[{deep_get(event, 'target_user', 'email', default = '<email_not_found>')}]"
        " from unmanaged IP Address."
    )
