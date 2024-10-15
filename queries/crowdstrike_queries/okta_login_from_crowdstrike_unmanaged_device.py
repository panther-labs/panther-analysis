def rule(_):
    return True


def title(event):
    return (
        "Okta Login for "
        f"[{event.deep_get('actor', 'alternateId', default = '<email_not_found>')}]"
        " from unmanaged IP Address."
    )
