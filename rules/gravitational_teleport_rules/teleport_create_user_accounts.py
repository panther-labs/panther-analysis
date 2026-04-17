from panther_base_helpers import pattern_match_list

USER_CREATE_PATTERNS = [
    "chage",  # user password expiry
    "passwd",  # change passwords for users
    "user*",  # create, modify, and delete users
]


def rule(event):
    # Filter the events
    if event.get("event") != "session.command":
        return False
    # Check that the program matches our list above
    return pattern_match_list(event.get("program", ""), USER_CREATE_PATTERNS)


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] has manually modified system users "
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
