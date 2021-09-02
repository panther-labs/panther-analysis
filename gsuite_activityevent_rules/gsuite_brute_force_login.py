from panther_base_helpers import deep_get

def rule(event):
    # Filter login events
    if event.get('type') != 'login':
        return False

    # Pattern match this event to the recon actions
    return bool(event.get('name') == 'login_failure')


def title(event):
    return (
        f"Brute force login suspected for user "
        f"[{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    )
