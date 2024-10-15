def rule(_):
    return True


def title(event):
    return (
        "1Password Login for "
        f"[{event.deep_get('target_user', 'email', default = '<email_not_found>')}]"
        " from unmanaged IP Address."
    )
